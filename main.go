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
	"bytes"
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
	config        = kingpin.Flag("acurite.config", "Configuration file name.").Default("").String()
	sampleExpiry  = kingpin.Flag("acurite.sample-expiry", "How long a sample is valid for.").Default("15m").Duration()

	defaultAcuriteConfig = acuriteConfig{}

	defaultMetricConfig = MetricConfig{}

	defaultCalibrateConfig = CalibrateConfig{
		Separator: ";",
		Regex:     MustNewRegexp("(.*)"),
	}

	defaultRelabelConfig = RelabelConfig{
		Action:      RelabelReplace,
		Separator:   ";",
		Regex:       MustNewRegexp("(.*)"),
		Replacement: "$1",
	}

	relabelTarget = regexp.MustCompile(`^(?:(?:[a-zA-Z_]|\$(?:{\w+}|\w+))+\w*)+$`)

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
	Metrics []*MetricConfig `yaml:"metrics,omitempty"`

	Relabeling []*RelabelConfig `yaml:"relabeling,omitempty"`

	Calibrations []*CalibrateConfig `yaml:"calibrations,omitempty"`

	// original is the input from which the config was parsed.
	original string
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

func (s *acuriteSample) String() string {
	lpStrings := make([]string, 0, len(s.Labels))
	for k, v := range s.Labels {
		lpStrings = append(lpStrings, fmt.Sprintf("%s=%q", k, v))
	}
	return fmt.Sprintf("%s{%s}", s.Name, lpStrings)
}

type acuriteCollector struct {
	samples map[acuriteSampleId]*acuriteSample
	mu      *sync.Mutex
	config  *acuriteConfig
	ch      chan *acuriteSample
}

// CalibrateConfig is the configuration for calibrating acurite samples.
type CalibrateConfig struct {
	// A list of labels from which values are taken and concatenated
	// with the configured separator in order.
	SourceLabels model.LabelNames `yaml:"source_labels,flow,omitempty"`
	// Separator is the string between concatenated values from the source labels.
	Separator string `yaml:"separator,omitempty"`
	// Regex against which the concatenation is matched.
	Regex Regexp `yaml:"regex,omitempty"`
	// Calibration is the value used to calibrate the sample.
	Calibration float64 `yaml:"calibration,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *CalibrateConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = defaultCalibrateConfig
	type plain CalibrateConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Regex.Regexp == nil {
		c.Regex = MustNewRegexp("")
	}

	return nil
}

// MetricType is the type of the metric.
type MetricType string

const (
	// Float metric type.
	Float MetricType = "float"
	// Integer metric type.
	Integer MetricType = "integer"
)

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (a *MetricType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch typ := MetricType(strings.ToLower(s)); typ {
	case Float, Integer:
		*a = typ
		return nil
	}
	return fmt.Errorf("unknown metric type %q", s)
}

// MetricMapping is the mapping of values from acurite metrics to prometheus values.
type MetricMapping struct {
	// Regex against which the value is matched.
	Regex Regexp `yaml:"regex,flow,omitempty"`
	// Replacement is the regex replacement pattern to be used.
	Replacement string `yaml:"replacement,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *MetricMapping) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = MetricMapping{}
	type plain MetricMapping
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Regex.Regexp == nil {
		c.Regex = MustNewRegexp("")
	}

	return nil
}

// MetricConfig is the configuration for acurite metrics.
type MetricConfig struct {
	// Source of the name of the metric in acurite.
	Source string `yaml:"source,flow,omitempty"`
	// Name is the name of the metric in prometheus.
	Name string `yaml:"name,omitempty"`
	// Help is the human readable description of the metric in prometheus.
	Help string `yaml:"help,omitempty"`
	// Type is the type of the metric.
	Type MetricType `yaml:"type,omitempty"`
	// Mapping of metric values.
	Mapping []MetricMapping `yaml:"mapping,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *MetricConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = defaultMetricConfig
	type plain MetricConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Source == "" {
		return fmt.Errorf("metric configuration requires 'source' value")
	}
	if c.Name == "" {
		return fmt.Errorf("metric configuration requires 'name' value")
	}
	if c.Help == "" {
		return fmt.Errorf("metric configuration requires 'help' value")
	}
	if c.Type == "" {
		return fmt.Errorf("metric configuration requires 'type' value")
	}

	return nil
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

func mapFromInteger(value string) (optional.Float64, error) {
	parsedValue, err := strconv.Atoi(value)
	if err != nil {
		return optional.Float64{}, err
	}
	return optional.NewFloat64(float64(parsedValue)), nil
}

func mapFromFloat(value string) (optional.Float64, error) {
	parsedValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return optional.Float64{}, err
	}
	return optional.NewFloat64(parsedValue), nil
}

func valueConvert(metricConfig *MetricConfig, rawValue string) (optional.Float64, error) {
	value := valueMap(metricConfig, rawValue)
	if !value.Present() {
		return optional.Float64{}, nil
	}
	v, _ := value.Get()
	if metricConfig.Type == Float {
		return mapFromFloat(v)
	} else if metricConfig.Type == Integer {
		return mapFromInteger(v)
	} else {
		return optional.Float64{}, fmt.Errorf("%q is invalid 'type' for metric", metricConfig.Type)
	}
}

func valueMap(metricConfig *MetricConfig, value string) optional.String {
	if len(metricConfig.Mapping) == 0 {
		return optional.NewString(value)
	}
	for _, mapping := range metricConfig.Mapping {
		indexes := mapping.Regex.FindStringSubmatchIndex(value)
		// If there is no match no replacement must take place.
		if indexes == nil {
			continue
		}
		res := mapping.Regex.ExpandString([]byte{}, mapping.Replacement, value, indexes)
		if len(res) == 0 {
			return optional.String{}
		}
		return optional.NewString(string(res))
	}
	return optional.NewString(value)
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
		for _, metricConfig := range c.config.Metrics {
			rawValue := values.Get(metricConfig.Source)
			if rawValue != "" {
				value, err := valueConvert(metricConfig, rawValue)
				if err != nil {
					log.Errorf("Failed to convert %s '%s' for %s sensor '%s' on hub '%s' to a %v: %s",
						metricConfig.Name, rawValue, sensorType, sensor, hub, metricConfig.Type, err)
					continue
				}
				value.If(func(f float64) {
					sampleId := acuriteSampleId{
						Hub:    hub,
						Sensor: sensor,
						Source: metricConfig.Source,
					}
					sampleLabels := make(map[string]string)
					for k, v := range labels {
						sampleLabels[k] = v
					}
					sampleLabels["__source"] = metricConfig.Source
					sampleLabels = relabel(sampleLabels, c.config.Relabeling...)
					if sampleLabels != nil {
						f := calibrate(&sampleId, sampleLabels, f, c.config.Calibrations...)
						sampleLabels = removeHiddenLabels(sampleLabels)
						if sampleLabels != nil {
							sample := acuriteSample{
								Id:        sampleId,
								Name:      fmt.Sprintf("acurite_sensor_%s", metricConfig.Name),
								Value:     f,
								Labels:    sampleLabels,
								Type:      prometheus.GaugeValue,
								Help:      metricConfig.Help,
								Timestamp: timestamp,
							}
							log.Debugf("Sample: %+v", sample)
							lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
							c.ch <- &sample
						}
					}
				})
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

		desc := prometheus.NewDesc(sample.Name, sample.Help, []string{}, sample.Labels)
		ch <- prometheus.MustNewConstMetric(desc, sample.Type, sample.Value)
	}
}

func (c acuriteCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lastProcessed.Desc()
}

func init() {
	prometheus.MustRegister(version.NewCollector("acurite_exporter"))
}

func loadConfig(s string) (*acuriteConfig, error) {
	cfg := &acuriteConfig{}
	*cfg = defaultAcuriteConfig

	err := yaml.UnmarshalStrict([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	cfg.original = s
	return cfg, nil
}

func loadConfigFile(filename string) (*acuriteConfig, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(string(content))
	if err != nil {
		return nil, fmt.Errorf("parsing YAML file %s: %v", filename, err)
	}
	return cfg, nil
}

func calibrate(sampleId *acuriteSampleId, labels map[string]string, value float64, cfgs ...*CalibrateConfig) float64 {
	for _, cfg := range cfgs {
		calibratedValue := calibrateFromConfig(labels, value, cfg)
		if calibratedValue.Present() {
			v, _ := calibratedValue.Get()
			log.Debugf("Calibrated %s from %v to %v", *sampleId, value, v)
			return v
		}
	}
	return value
}

func calibrateFromConfig(labels map[string]string, value float64, cfg *CalibrateConfig) optional.Float64 {
	values := make([]string, 0, len(cfg.SourceLabels))
	for _, ln := range cfg.SourceLabels {
		values = append(values, labels[string(ln)])
	}
	val := strings.Join(values, cfg.Separator)
	if cfg.Regex.MatchString(val) {
		return optional.NewFloat64(value + cfg.Calibration)
	}

	return optional.Float64{}
}

func removeHiddenLabels(labels map[string]string) map[string]string {
	lb := make(map[string]string)
	for name, value := range labels {
		if !strings.HasPrefix(name, "__") {
			lb[name] = value
		}
	}
	return lb
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

func rewriteBody(resp *http.Response) (err error) {
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Debugf("Acurite Response: %s", string(b))

	err = resp.Body.Close()
	if err != nil {
		return err
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(b))
	return nil
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
	proxy.ModifyResponse = rewriteBody

	c := newAcuriteCollector()
	prometheus.MustRegister(c)

	c.config = &acuriteConfig{}
	if *config != "" {
		acuriteConfig, err := loadConfigFile(*config)
		if err != nil {
			log.Fatalf("Error loading config: %s", err)
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
