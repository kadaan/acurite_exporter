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
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	samplePath = "/weatherstation/updateweatherstation"
)

var (
	listenAddress = kingpin.Flag("web.listen-address", "Address on which to expose metrics.").Default(":9519").String()
	metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose Prometheus metrics.").Default("/metrics").String()
	sampleExpiry  = kingpin.Flag("acurite.sample-expiry", "How long a sample is valid for.").Default("15m").Duration()

	acuriteSampleMappings = []acuriteSampleMapping{
		{"sensorbattery", "battery", "", float, prometheus.GaugeValue,
			func(hub string, sensorType string, sensor string, name string, value string) optional.Float64 {
				switch value {
				case "low":
					return optional.NewFloat64(0)
				case "normal":
					return optional.NewFloat64(1)
				default:
					log.Warnf("Unsupported %s value '%s' for %s sensor '%s' on hub '%s'", name, value, sensorType, sensor, hub)
					return optional.Float64{}
				}
			}},
		{"tempf", "temperature", "", float, prometheus.GaugeValue, mapFromFloat},
		{"humidity", "humidity", "", integer, prometheus.GaugeValue, mapFromInteger},
		{"dewptf", "dewpoint", "", float, prometheus.GaugeValue, mapFromFloat},
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
	sampleInvalidMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acurite_sample_invalid_total",
			Help: "Total number of samples that were invalid.",
		},
		[]string{"hub", "type", "sensor"},
	)
	sampleInvalidValueMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acurite_sample_invalid_value_total",
			Help: "Total number of sample values that were invalid.",
		},
		[]string{"hub", "type", "sensor", "name"},
	)
)

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
	ch      chan *acuriteSample
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

func mapFromInteger(hub string, sensorType string, sensor string, name string, value string) optional.Float64 {
	parsedValue, err := strconv.Atoi(value)
	if err != nil {
		return optional.Float64{}
	}
	return optional.NewFloat64(float64(parsedValue))
}

func mapFromFloat(hub string, sensorType string, sensor string, name string, value string) optional.Float64 {
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
			sampleInvalidMetric.WithLabelValues(hub, sensorType, sensor).Inc()
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
					sampleInvalidValueMetric.WithLabelValues(hub, sensorType, sensor, acuriteSampleMapping.Name).Inc()
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
		ch <- prometheus.NewMetricWithTimestamp(sample.Timestamp,
			prometheus.MustNewConstMetric(
				prometheus.NewDesc(sample.Name, sample.Help, []string{}, sample.Labels),
				sample.Type,
				sample.Value,
			),
		)
	}
}

func (c acuriteCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lastProcessed.Desc()
}

func init() {
	prometheus.MustRegister(version.NewCollector("acurite_exporter"))
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
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
