// Copyright © 2018 Joel Baranick <jbaranick@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"github.com/markphelps/optional"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	samplePath = "/weatherstation/updateweatherstation"
)

var (
	listenAddress = kingpin.Flag("web.listen-address", "Address on which to expose metrics.").Default(":9519").String()
	metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose Prometheus metrics.").Default("/metrics").String()
	relabelConfig = kingpin.Flag("acurite.relabel-config", "Metric relabel configuration file name.").Default("").String()
	sampleExpiry  = kingpin.Flag("acurite.sample-expiry", "How long a sample is valid for.").Default("15m").Duration()

	defaultConfig = acuriteConfig{}

	defaultRelabelConfig = RelabelConfig{
		Action:      RelabelReplace,
		Separator:   ";",
		Regex:       MustNewRegexp("(.*)"),
		Replacement: "$1",
	}

	relabelTarget = regexp.MustCompile(`^(?:(?:[a-zA-Z_]|\$(?:{\w+}|\w+))+\w*)+$`)

	acuriteSampleMappings = []acuriteSampleMapping{
		{"sensorbattery", "battery_low", "1 if the sensor battery is low.", float, prometheus.GaugeValue,
			func(hub string, sensorType string, sensor string, name string, value string) optional.Float64 {
				switch value {
				case "low":
					return optional.NewFloat64(1)
				case "normal":
					return optional.NewFloat64(0)
				default:
					log.Warnf("Unsupported %s value '%s' for %s sensor '%s' on hub '%s'", name, value, sensorType, sensor, hub)
					return optional.Float64{}
				}
			}},
		{"tempf", "temperature_fahrenheit", "Temperature in fahrenheit as detected by the sensor.", float, prometheus.GaugeValue, mapFromFloat},
		{"humidity", "humidity_percentage", "Humidity percentage as detected by the sensor.", integer, prometheus.GaugeValue, mapFromInteger},
		{"dewptf", "dewpoint_fahrenheit", "Dew point in fahrenheit as detected by the sensor.", float, prometheus.GaugeValue, mapFromFloat},
	}

	lastProcessed = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "acurite_last_processed_timestamp_seconds",
			Help: "Unix timestamp of the last processed acurite metric.",
		},
	)
	sampleExpiryMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "acurite_sample_expiry_seconds",
			Help: "How long in seconds a metric sample is valid for.",
		},
	)
	sampleInvalidMetric = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "acurite_sample_invalid_total",
			Help: "Total number of samples that were invalid.",
		},
	)
)

type acuriteConfig struct {
	RelabelConfigs []*RelabelConfig `yaml:"relabel_configs,omitempty"`

	// original is the input from which the config was parsed.
	original string
}

type acuriteValueType int

const (
	_ acuriteValueType = iota
	float
	integer
)

type acuriteSampleMapping struct {
	Source             string
	Name               string
	Help               string
	ValueType          acuriteValueType
	MetricType         prometheus.ValueType
	ConversionFunction func(hub string, sensorType string, sensor string, name string, value string) optional.Float64
}

type acuriteSampleId struct {
	Hub    string
	Sensor string
	Source string
}

type acuriteSample struct {
	Id        acuriteSampleId
	Name      string
	Labels    map[string]string
	Help      string
	Value     float64
	Type      prometheus.ValueType
	Timestamp time.Time
}

type acuriteCollector struct {
	samples map[acuriteSampleId]*acuriteSample
	mu      *sync.Mutex
	config  *acuriteConfig
	ch      chan *acuriteSample
}

// RelabelAction is the action to be performed on relabeling.
type RelabelAction string

const (
	// RelabelReplace performs a regex replacement.
	RelabelReplace RelabelAction = "replace"
	// RelabelKeep drops targets for which the input does not match the regex.
	RelabelKeep RelabelAction = "keep"
	// RelabelDrop drops targets for which the input does match the regex.
	RelabelDrop RelabelAction = "drop"
	// RelabelLabelMap copies labels to other labelnames based on a regex.
	RelabelLabelMap RelabelAction = "labelmap"
	// RelabelLabelDrop drops any label matching the regex.
	RelabelLabelDrop RelabelAction = "labeldrop"
	// RelabelLabelKeep drops any label not matching the regex.
	RelabelLabelKeep RelabelAction = "labelkeep"
)

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (a *RelabelAction) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch act := RelabelAction(strings.ToLower(s)); act {
	case RelabelReplace, RelabelKeep, RelabelDrop, RelabelLabelMap, RelabelLabelDrop, RelabelLabelKeep:
		*a = act
		return nil
	}
	return fmt.Errorf("unknown relabel action %q", s)
}

// RelabelConfig is the configuration for relabeling of target label sets.
type RelabelConfig struct {
	// A list of labels from which values are taken and concatenated
	// with the configured separator in order.
	SourceLabels model.LabelNames `yaml:"source_labels,flow,omitempty"`
	// Separator is the string between concatenated values from the source labels.
	Separator string `yaml:"separator,omitempty"`
	// Regex against which the concatenation is matched.
	Regex Regexp `yaml:"regex,omitempty"`
	// Modulus to take of the hash of concatenated values from the source labels.
	Modulus uint64 `yaml:"modulus,omitempty"`
	// TargetLabel is the label to which the resulting string is written in a replacement.
	// Regexp interpolation is allowed for the replace action.
	TargetLabel string `yaml:"target_label,omitempty"`
	// Replacement is the regex replacement pattern to be used.
	Replacement string `yaml:"replacement,omitempty"`
	// Action is the action to be performed for the relabeling.
	Action RelabelAction `yaml:"action,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *RelabelConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = defaultRelabelConfig
	type plain RelabelConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Regex.Regexp == nil {
		c.Regex = MustNewRegexp("")
	}
	if c.Action == RelabelReplace && c.TargetLabel == "" {
		return fmt.Errorf("relabel configuration for %s action requires 'target_label' value", c.Action)
	}
	if c.Action == RelabelReplace && !relabelTarget.MatchString(c.TargetLabel) {
		return fmt.Errorf("%q is invalid 'target_label' for %s action", c.TargetLabel, c.Action)
	}
	if c.Action == RelabelLabelMap && !relabelTarget.MatchString(c.Replacement) {
		return fmt.Errorf("%q is invalid 'replacement' for %s action", c.Replacement, c.Action)
	}

	if c.Action == RelabelLabelDrop || c.Action == RelabelLabelKeep {
		if c.SourceLabels != nil ||
			c.TargetLabel != defaultRelabelConfig.TargetLabel ||
			c.Separator != defaultRelabelConfig.Separator ||
			c.Replacement != defaultRelabelConfig.Replacement {
			return fmt.Errorf("%s action requires only 'regex', and no other fields", c.Action)
		}
	}

	return nil
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
	original string
}

// NewRegexp creates a new anchored Regexp and returns an error if the
// passed-in regular expression does not compile.
func NewRegexp(s string) (Regexp, error) {
	regex, err := regexp.Compile("^(?:" + s + ")$")
	return Regexp{
		Regexp:   regex,
		original: s,
	}, err
}

// MustNewRegexp works like NewRegexp, but panics if the regular expression does not compile.
func MustNewRegexp(s string) Regexp {
	re, err := NewRegexp(s)
	if err != nil {
		panic(err)
	}
	return re
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	r, err := NewRegexp(s)
	if err != nil {
		return err
	}
	*re = r
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (re Regexp) MarshalYAML() (interface{}, error) {
	if re.original != "" {
		return re.original, nil
	}
	return nil, nil
}

func newAcuriteCollector() *acuriteCollector {
	c := &acuriteCollector{
		ch:      make(chan *acuriteSample, 0),
		mu:      &sync.Mutex{},
		samples: map[acuriteSampleId]*acuriteSample{},
	}
	go c.processSamples()
	return c
}

func mapFromInteger(_ string, _ string, _ string, _ string, value string) optional.Float64 {
	parsedValue, err := strconv.Atoi(value)
	if err != nil {
		return optional.Float64{}
	}
	return optional.NewFloat64(float64(parsedValue))
}

func mapFromFloat(_ string, _ string, _ string, _ string, value string) optional.Float64 {
	parsedValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return optional.Float64{}
	}
	return optional.NewFloat64(parsedValue)
}

func (c *acuriteCollector) processSample(sample string, values url.Values) {
	log.Debugf("Incoming sample: %s", sample)
	hub := values.Get("id")
	sensorType := values.Get("mt")
	if sensorType == "5N1" || sensorType == "Atlas" || sensorType == "tower" || sensorType == "ProOut" || sensorType == "ProIn" {
		sensor := values.Get("sensor")
		dateutc := values.Get("dateutc")
		timestamp, err := time.Parse("2006-01-02T15:04:05", dateutc)
		if err != nil {
			log.Errorf("Failed to convert dateutc '%s' for %s sensor '%s' on hub '%s' to a Time: %s",
				dateutc, sensorType, sensor, hub, err)
			sampleInvalidMetric.Inc()
			return
		}

		labels := map[string]string{
			"hub":    hub,
			"type":   sensorType,
			"sensor": sensor,
		}
		for _, acuriteSampleMapping := range acuriteSampleMappings {
			rawValue := values.Get(acuriteSampleMapping.Source)
			if rawValue != "" {
				value := acuriteSampleMapping.ConversionFunction(hub, sensorType, sensor, acuriteSampleMapping.Source, rawValue)
				if value.Present() {
					value.If(func(f float64) {
						sampleId := acuriteSampleId{
							Hub:    hub,
							Sensor: sensor,
							Source: acuriteSampleMapping.Source,
						}
						sample := acuriteSample{
							Id:        sampleId,
							Name:      fmt.Sprintf("acurite_sensor_%s", acuriteSampleMapping.Name),
							Value:     f,
							Labels:    labels,
							Type:      acuriteSampleMapping.MetricType,
							Help:      acuriteSampleMapping.Help,
							Timestamp: timestamp,
						}
						log.Debugf("Sample: %+v", sample)
						lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
						c.ch <- &sample
					})
				} else {
					log.Errorf("Failed to convert %s '%s' for %s sensor '%s' on hub '%s' to a %v: %s",
						acuriteSampleMapping.Name, rawValue, sensorType, sensor, hub, acuriteSampleMapping.ValueType, err)
					sampleInvalidMetric.Inc()
				}
			}
		}
	}
}

func (c *acuriteCollector) processSamples() {
	ticker := time.NewTicker(time.Minute).C

	for {
		select {
		case sample, ok := <-c.ch:
			if sample == nil || ok != true {
				return
			}
			c.mu.Lock()
			c.samples[sample.Id] = sample
			c.mu.Unlock()
		case <-ticker:
			// Garbage collect expired samples.
			ageLimit := time.Now().Add(-*sampleExpiry)
			c.mu.Lock()
			for k, sample := range c.samples {
				if ageLimit.After(sample.Timestamp) {
					delete(c.samples, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c acuriteCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- lastProcessed

	c.mu.Lock()
	samples := make([]*acuriteSample, 0, len(c.samples))
	for _, sample := range c.samples {
		samples = append(samples, sample)
	}
	c.mu.Unlock()

	ageLimit := time.Now().Add(-*sampleExpiry)
	for _, sample := range samples {
		if ageLimit.After(sample.Timestamp) {
			continue
		}

		labels := relabel(sample.Labels, c.config.RelabelConfigs...)
		if labels != nil {
			desc := prometheus.NewDesc(sample.Name, sample.Help, []string{}, labels)
			ch <- prometheus.MustNewConstMetric(desc, sample.Type, sample.Value)
		}
	}
}

func (c acuriteCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lastProcessed.Desc()
}

func init() {
	prometheus.MustRegister(version.NewCollector("acurite_exporter"))
}

func load(s string) (*acuriteConfig, error) {
	cfg := &acuriteConfig{}
	*cfg = defaultConfig

	err := yaml.UnmarshalStrict([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	cfg.original = s
	return cfg, nil
}

func loadFile(filename string) (*acuriteConfig, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := load(string(content))
	if err != nil {
		return nil, fmt.Errorf("parsing YAML file %s: %v", filename, err)
	}
	return cfg, nil
}

func relabel(labels map[string]string, cfgs ...*RelabelConfig) map[string]string {
	for _, cfg := range cfgs {
		labels = relabelFromConfig(labels, cfg)
		if labels == nil {
			return nil
		}
	}
	return labels
}

func relabelFromConfig(labels map[string]string, cfg *RelabelConfig) map[string]string {
	values := make([]string, 0, len(cfg.SourceLabels))
	for _, ln := range cfg.SourceLabels {
		values = append(values, labels[string(ln)])
	}
	val := strings.Join(values, cfg.Separator)

	lb := make(map[string]string)
	for name, value := range labels {
		lb[name] = value
	}

	switch cfg.Action {
	case RelabelDrop:
		if cfg.Regex.MatchString(val) {
			return nil
		}
	case RelabelKeep:
		if !cfg.Regex.MatchString(val) {
			return nil
		}
	case RelabelReplace:
		indexes := cfg.Regex.FindStringSubmatchIndex(val)
		// If there is no match no replacement must take place.
		if indexes == nil {
			break
		}
		target := model.LabelName(cfg.Regex.ExpandString([]byte{}, cfg.TargetLabel, val, indexes))
		if !target.IsValid() {
			delete(lb, cfg.TargetLabel)
			break
		}
		res := cfg.Regex.ExpandString([]byte{}, cfg.Replacement, val, indexes)
		if len(res) == 0 {
			delete(lb, cfg.TargetLabel)
			break
		}
		lb[string(target)] = string(res)
	case RelabelLabelMap:
		relabelLabelMap(labels, cfg, lb)
	case RelabelLabelDrop:
		relabelLabelDrop(labels, cfg, lb)
	case RelabelLabelKeep:
		relabelLabelKeep(labels, cfg, lb)
	default:
		panic(fmt.Errorf("relabel: unknown relabel action type %q", cfg.Action))
	}

	return lb
}

func relabelLabelMap(labels map[string]string, cfg *RelabelConfig, lb map[string]string) {
	for name, value := range labels {
		if cfg.Regex.MatchString(name) {
			res := cfg.Regex.ReplaceAllString(name, cfg.Replacement)
			lb[res] = value
		}
	}
}

func relabelLabelDrop(labels map[string]string, cfg *RelabelConfig, lb map[string]string) {
	for name := range labels {
		if cfg.Regex.MatchString(name) {
			delete(lb, name)
		}
	}
}

func relabelLabelKeep(labels map[string]string, cfg *RelabelConfig, lb map[string]string) {
	for name := range labels {
		if !cfg.Regex.MatchString(name) {
			delete(lb, name)
		}
	}
}

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("acurite_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	prometheus.MustRegister(sampleExpiryMetric)
	sampleExpiryMetric.Set(sampleExpiry.Seconds())

	prometheus.MustRegister(sampleInvalidMetric)

	log.Infoln("Starting acurite_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	http.Handle(*metricsPath, promhttp.Handler())

	upstreamUrl, _ := url.Parse("https://atlasapi.myacurite.com")
	proxy := httputil.NewSingleHostReverseProxy(upstreamUrl)

	c := newAcuriteCollector()
	prometheus.MustRegister(c)

	c.config = &acuriteConfig{}
	if *relabelConfig != "" {
		acuriteConfig, err := loadFile(*relabelConfig)
		if err != nil {
			log.Fatalf("Error loading metric relabel config: %s", err)
		}
		c.config = acuriteConfig
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
      <head><title>Acurite Exporter</title></head>
      <body>
      <h1>Acurite Exporter</h1>
      <p>Accepting Acurite samples at ` + samplePath + `</p>
      <p><a href="` + *metricsPath + `">Metrics</a></p>
      </body>
      </html>`))
	})
	http.HandleFunc(samplePath, func(w http.ResponseWriter, r *http.Request) {
		c.processSample(r.URL.RawQuery, r.URL.Query())
		proxy.ServeHTTP(w, r)
	})

	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
