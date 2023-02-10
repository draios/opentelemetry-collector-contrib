// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysdig

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestAddSingleGaugeNumberDataPoint(t *testing.T) {
	ts := uint64(time.Now().UnixNano())
	labelArr := []prompb.Label{
		{Name: model.MetricNameLabel, Value: "test"},
	}
	tests := []struct {
		name     string
		metric   func() pmetric.Metric
		wantedTs func() map[string]*prompb.TimeSeries
		wantedMd func() map[string]*prompb.MetricMetadata
	}{
		{
			name: "gauge",
			metric: func() pmetric.Metric {
				return getIntGaugeMetric(
					labelArr[0].Value,
					pcommon.NewMap(),
					1, ts,
				)
			},
			wantedTs: func() map[string]*prompb.TimeSeries {
				labels := labelArr
				return map[string]*prompb.TimeSeries{
					timeSeriesSignature(pmetric.MetricTypeGauge.String(), &labels): {
						Labels: labels,
						Samples: []prompb.Sample{
							{
								Value:     1,
								Timestamp: convertTimeStamp(pcommon.Timestamp(ts)),
							}},
					},
				}
			},
			wantedMd: func() map[string]*prompb.MetricMetadata {
				labels := labelArr
				return map[string]*prompb.MetricMetadata{
					timeSeriesSignature(pmetric.MetricTypeGauge.String(), &labels): {
						Type:             prompb.MetricMetadata_GAUGE,
						MetricFamilyName: "test",
					},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metric := tt.metric()

			tsMap := make(map[string]*prompb.TimeSeries)
			mdMap := make(map[string]*prompb.MetricMetadata)

			for x := 0; x < metric.Gauge().DataPoints().Len(); x++ {
				addSingleGaugeNumberDataPoint(
					metric.Gauge().DataPoints().At(x),
					pcommon.NewResource(),
					metric,
					Settings{},
					tsMap,
					mdMap,
				)
			}
			assert.Equal(t, tt.wantedTs(), tsMap)
			assert.Equal(t, tt.wantedMd(), mdMap)
		})
	}
}

func TestAddSingleSumNumberDataPoint(t *testing.T) {
	ts := pcommon.Timestamp(time.Now().UnixNano())
	labelArr := []prompb.Label{
		{Name: model.MetricNameLabel, Value: "test"},
	}
	tests := []struct {
		name     string
		metric   func() pmetric.Metric
		wantedTs func() map[string]*prompb.TimeSeries
		wantedMd func() map[string]*prompb.MetricMetadata
	}{
		{
			name: "sum",
			metric: func() pmetric.Metric {
				return getIntSumMetric(
					labelArr[0].Value,
					pcommon.NewMap(),
					pmetric.AggregationTemporalityCumulative,
					1, uint64(ts.AsTime().UnixNano()),
				)
			},
			wantedTs: func() map[string]*prompb.TimeSeries {
				labels := labelArr
				return map[string]*prompb.TimeSeries{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Labels: labels,
						Samples: []prompb.Sample{
							{
								Value:     1,
								Timestamp: convertTimeStamp(ts),
							}},
					},
				}
			},
			wantedMd: func() map[string]*prompb.MetricMetadata {
				labels := labelArr
				return map[string]*prompb.MetricMetadata{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Type:             prompb.MetricMetadata_COUNTER,
						MetricFamilyName: "test",
					},
				}
			},
		},
		{
			name: "sum with exemplars",
			metric: func() pmetric.Metric {
				m := getIntSumMetric(
					"test",
					pcommon.NewMap(),
					pmetric.AggregationTemporalityCumulative,
					1, uint64(ts.AsTime().UnixNano()),
				)
				m.Sum().DataPoints().At(0).Exemplars().AppendEmpty().SetDoubleValue(2)
				return m
			},
			wantedTs: func() map[string]*prompb.TimeSeries {
				labels := labelArr
				return map[string]*prompb.TimeSeries{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Labels: labels,
						Samples: []prompb.Sample{{
							Value:     1,
							Timestamp: convertTimeStamp(ts),
						}},
						Exemplars: []prompb.Exemplar{
							{Value: 2},
						},
					},
				}
			},
			wantedMd: func() map[string]*prompb.MetricMetadata {
				labels := labelArr
				return map[string]*prompb.MetricMetadata{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Type:             prompb.MetricMetadata_COUNTER,
						MetricFamilyName: "test",
					},
				}
			},
		},
		{
			name: "monotonic cumulative sum with start timestamp",
			metric: func() pmetric.Metric {
				metric := pmetric.NewMetric()
				metric.SetName("test_sum")
				metric.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				metric.SetEmptySum().SetIsMonotonic(true)

				dp := metric.Sum().DataPoints().AppendEmpty()
				dp.SetDoubleValue(1)
				dp.SetTimestamp(ts)
				dp.SetStartTimestamp(ts)

				return metric
			},
			wantedTs: func() map[string]*prompb.TimeSeries {
				labels := []prompb.Label{
					{Name: model.MetricNameLabel, Value: "test_sum"},
				}
				createdLabels := []prompb.Label{
					{Name: model.MetricNameLabel, Value: "test_sum" + createdSuffix},
				}
				return map[string]*prompb.TimeSeries{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Labels: labels,
						Samples: []prompb.Sample{
							{Value: 1, Timestamp: convertTimeStamp(ts)},
						},
					},
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &createdLabels): {
						Labels: createdLabels,
						Samples: []prompb.Sample{
							{Value: float64(convertTimeStamp(ts))},
						},
					},
				}
			},
			wantedMd: func() map[string]*prompb.MetricMetadata {
				labels := []prompb.Label{
					{Name: model.MetricNameLabel, Value: "test_sum"},
				}
				createdLabels := []prompb.Label{
					{Name: model.MetricNameLabel, Value: "test_sum" + createdSuffix},
				}
				return map[string]*prompb.MetricMetadata{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Type:             prompb.MetricMetadata_COUNTER,
						MetricFamilyName: "test_sum",
					},
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &createdLabels): {
						Type:             prompb.MetricMetadata_COUNTER,
						MetricFamilyName: "test_sum",
					},
				}
			},
		},
		{
			name: "monotonic cumulative sum with no start time",
			metric: func() pmetric.Metric {
				metric := pmetric.NewMetric()
				metric.SetName("test")
				metric.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				metric.SetEmptySum().SetIsMonotonic(true)

				dp := metric.Sum().DataPoints().AppendEmpty()
				dp.SetTimestamp(ts)

				return metric
			},
			wantedTs: func() map[string]*prompb.TimeSeries {
				labels := labelArr
				return map[string]*prompb.TimeSeries{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Labels: labels,
						Samples: []prompb.Sample{
							{Value: 0, Timestamp: convertTimeStamp(ts)},
						},
					},
				}
			},
			wantedMd: func() map[string]*prompb.MetricMetadata {
				labels := labelArr
				return map[string]*prompb.MetricMetadata{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Type:             prompb.MetricMetadata_COUNTER,
						MetricFamilyName: "test",
					},
				}
			},
		},
		{
			name: "non-monotonic cumulative sum with start time",
			metric: func() pmetric.Metric {
				metric := pmetric.NewMetric()
				metric.SetName("test")
				metric.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				metric.SetEmptySum().SetIsMonotonic(false)

				dp := metric.Sum().DataPoints().AppendEmpty()
				dp.SetTimestamp(ts)

				return metric
			},
			wantedTs: func() map[string]*prompb.TimeSeries {
				labels := labelArr
				return map[string]*prompb.TimeSeries{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Labels: labels,
						Samples: []prompb.Sample{
							{Value: 0, Timestamp: convertTimeStamp(ts)},
						},
					},
				}
			},
			wantedMd: func() map[string]*prompb.MetricMetadata {
				labels := labelArr
				return map[string]*prompb.MetricMetadata{
					timeSeriesSignature(pmetric.MetricTypeSum.String(), &labels): {
						Type:             prompb.MetricMetadata_COUNTER,
						MetricFamilyName: "test",
					},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metric := tt.metric()

			tsMap := make(map[string]*prompb.TimeSeries)
			mdMap := make(map[string]*prompb.MetricMetadata)

			for x := 0; x < metric.Sum().DataPoints().Len(); x++ {
				addSingleSumNumberDataPoint(
					metric.Sum().DataPoints().At(x),
					pcommon.NewResource(),
					metric,
					Settings{ExportCreatedMetric: true},
					tsMap,
					mdMap,
				)
			}
			assert.Equal(t, tt.wantedTs(), tsMap)
			assert.Equal(t, tt.wantedMd(), mdMap)
		})
	}
}
