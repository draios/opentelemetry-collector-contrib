// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysdig // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/sysdig"

import (
	"errors"
	"fmt"

	prometheustranslator "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/prometheus"
	"github.com/prometheus/prometheus/prompb"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/multierr"
)

type Settings struct {
	Namespace           string
	ExternalLabels      map[string]string
	DisableTargetInfo   bool
	ExportCreatedMetric bool
}

// FromMetrics converts pmetric.Metrics to prometheus remote write format.
func FromMetrics(md pmetric.Metrics, settings Settings) (tsMap map[string]*prompb.TimeSeries, mdMap map[string]*prompb.MetricMetadata, errs error) {
	tsMap = make(map[string]*prompb.TimeSeries)
	mdMap = make(map[string]*prompb.MetricMetadata)

	resourceMetricsSlice := md.ResourceMetrics()
	for i := 0; i < resourceMetricsSlice.Len(); i++ {
		resourceMetrics := resourceMetricsSlice.At(i)
		resource := resourceMetrics.Resource()
		scopeMetricsSlice := resourceMetrics.ScopeMetrics()
		// keep track of the most recent timestamp in the ResourceMetrics for
		// use with the "target" info metric
		var mostRecentTimestamp pcommon.Timestamp
		for j := 0; j < scopeMetricsSlice.Len(); j++ {
			scopeMetrics := scopeMetricsSlice.At(j)
			metricSlice := scopeMetrics.Metrics()

			// TODO: decide if instrumentation library information should be exported as labels
			for k := 0; k < metricSlice.Len(); k++ {
				metric := metricSlice.At(k)
				mostRecentTimestamp = maxTimestamp(mostRecentTimestamp, mostRecentTimestampInMetric(metric))

				if !isValidAggregationTemporality(metric) {
					errs = multierr.Append(errs, errors.New("invalid temporality and type combination"))
					continue
				}

				// handle individual metric based on type
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					dataPoints := metric.Gauge().DataPoints()
					if dataPoints.Len() == 0 {
						errs = multierr.Append(errs, fmt.Errorf("empty data points. %s is dropped", metric.Name()))
					}
					for x := 0; x < dataPoints.Len(); x++ {
						addSingleGaugeNumberDataPoint(dataPoints.At(x), resource, metric, settings, tsMap, mdMap)
					}
				case pmetric.MetricTypeSum:
					if metric.Sum().AggregationTemporality() == pmetric.AggregationTemporalityDelta {
						dataPoints := metric.Gauge().DataPoints()
						if dataPoints.Len() == 0 {
							errs = multierr.Append(errs, fmt.Errorf("empty data points. %s is dropped", metric.Name()))
						}
						metric.SetUnit("delta_counter:" + metric.Unit())
						for x := 0; x < dataPoints.Len(); x++ {
							addSingleGaugeNumberDataPoint(dataPoints.At(x), resource, metric, settings, tsMap, mdMap)
						}
					} else {
						dataPoints := metric.Sum().DataPoints()
						if dataPoints.Len() == 0 {
							errs = multierr.Append(errs, fmt.Errorf("empty data points. %s is dropped", metric.Name()))
						}
						for x := 0; x < dataPoints.Len(); x++ {
							addSingleSumNumberDataPoint(dataPoints.At(x), resource, metric, settings, tsMap, mdMap)
						}
					}
				case pmetric.MetricTypeHistogram:
					dataPoints := metric.Histogram().DataPoints()
					if dataPoints.Len() == 0 {
						errs = multierr.Append(errs, fmt.Errorf("empty data points. %s is dropped", metric.Name()))
					}
					for x := 0; x < dataPoints.Len(); x++ {
						addSingleHistogramDataPoint(dataPoints.At(x), resource, metric, settings, tsMap, mdMap)
					}
				case pmetric.MetricTypeExponentialHistogram:
					dataPoints := metric.ExponentialHistogram().DataPoints()
					if dataPoints.Len() == 0 {
						errs = multierr.Append(errs, fmt.Errorf("empty data points. %s is dropped", metric.Name()))
					}
					name := prometheustranslator.BuildPromCompliantName(metric, settings.Namespace)
					for x := 0; x < dataPoints.Len(); x++ {
						errs = multierr.Append(
							errs,
							addSingleExponentialHistogramDataPoint(
								name,
								metric,
								dataPoints.At(x),
								resource,
								settings,
								tsMap,
								mdMap,
							),
						)
					}
				case pmetric.MetricTypeSummary:
					dataPoints := metric.Summary().DataPoints()
					if dataPoints.Len() == 0 {
						errs = multierr.Append(errs, fmt.Errorf("empty data points. %s is dropped", metric.Name()))
					}
					for x := 0; x < dataPoints.Len(); x++ {
						addSingleSummaryDataPoint(dataPoints.At(x), resource, metric, settings, tsMap, mdMap)
					}
				default:
					errs = multierr.Append(errs, errors.New("unsupported metric type"))
				}
			}
		}
		addResourceTargetInfo(resource, settings, mostRecentTimestamp, tsMap)
	}

	return
}
