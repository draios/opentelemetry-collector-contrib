// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysdigexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/sysdigexporter"

import (
	"context"
	"errors"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
)

const (
	// The value of "type" key in configuration.
	typeStr = "sysdig"
	// The stability level of the exporter.
	stability = component.StabilityLevelBeta
)

// NewFactory creates a new Sysdig Prometheus Remote Write exporter.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		typeStr,
		createDefaultConfig,
		exporter.WithMetrics(createMetricsExporter, stability))
}

func createMetricsExporter(ctx context.Context, set exporter.CreateSettings, cfg component.Config) (exporter.Metrics, error) {
	sysdigCfg, ok := cfg.(*Config)
	if !ok {
		return nil, errors.New("invalid configuration")
	}

	// create the sysdig exporter
	sysdigExporter, err := newSysdigExporter(sysdigCfg, set)
	if err != nil {
		return nil, err
	}

	// Don't allow users to configure the queue.
	// See https://github.com/open-telemetry/opentelemetry-collector/issues/2949.
	// Prometheus remote write samples needs to be in chronological
	// order for each timeseries. If we shard the incoming metrics
	// without considering this limitation, we experience
	// "out of order samples" errors.
	exp, err := exporterhelper.NewMetricsExporter(
		ctx,
		set,
		cfg,
		sysdigExporter.PushMetrics,
		exporterhelper.WithTimeout(sysdigCfg.TimeoutSettings),
		exporterhelper.WithQueue(exporterhelper.QueueSettings{
			Enabled:      sysdigCfg.RemoteWriteQueue.Enabled,
			NumConsumers: 1,
			QueueSize:    sysdigCfg.RemoteWriteQueue.QueueSize,
		}),
		exporterhelper.WithRetry(sysdigCfg.RetrySettings),
		exporterhelper.WithStart(sysdigExporter.Start),
		exporterhelper.WithShutdown(sysdigExporter.Shutdown),
	)
	if err != nil {
		return nil, err
	}
	return resourcetotelemetry.WrapMetricsExporter(sysdigCfg.ResourceToTelemetrySettings, exp), nil
}

func createDefaultConfig() component.Config {
	return &Config{
		Namespace:       "",
		ExternalLabels:  map[string]string{},
		TimeoutSettings: exporterhelper.NewDefaultTimeoutSettings(),
		RetrySettings: exporterhelper.RetrySettings{
			Enabled:         true,
			InitialInterval: 50 * time.Millisecond,
			MaxInterval:     200 * time.Millisecond,
			MaxElapsedTime:  1 * time.Minute,
		},
		HTTPClientSettings: confighttp.HTTPClientSettings{
			Endpoint: "http://some.url:9411/api/prom/push",
			// We almost read 0 bytes, so no need to tune ReadBufferSize.
			ReadBufferSize:  0,
			WriteBufferSize: 512 * 1024,
			Timeout:         exporterhelper.NewDefaultTimeoutSettings().Timeout,
			Headers:         map[string]configopaque.String{},
		},
		// TODO(jbd): Adjust the default queue size.
		RemoteWriteQueue: RemoteWriteQueue{
			Enabled:      true,
			QueueSize:    10000,
			NumConsumers: 5,
		},
		TargetInfo: &TargetInfo{
			Enabled: true,
		},
		Name:        "sysdig-remote-write",
		BearerToken: "token",
	}
}
