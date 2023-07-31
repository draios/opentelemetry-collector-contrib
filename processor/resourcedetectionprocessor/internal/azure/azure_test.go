// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/processor/processortest"
	conventions "go.opentelemetry.io/collector/semconv/v1.6.1"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/metadataproviders/azure"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor/internal"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor/internal/azure/internal/metadata"
)

func TestNewDetector(t *testing.T) {
	dcfg := CreateDefaultConfig()
	d, err := NewDetector(processortest.NewNopCreateSettings(), dcfg)
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestDetectAzureAvailable(t *testing.T) {
	mp := &azure.MockProvider{}
	mp.On("Metadata").Return(&azure.ComputeMetadata{
		Location:          "location",
		Name:              "name",
		VMID:              "vmID",
		VMSize:            "vmSize",
		SubscriptionID:    "subscriptionID",
		ResourceGroupName: "resourceGroup",
		VMScaleSetName:    "myScaleset",
	}, nil)

	detector := &Detector{provider: mp, rb: metadata.NewResourceBuilder(metadata.DefaultResourceAttributesConfig())}
	res, schemaURL, err := detector.Detect(context.Background())
	require.NoError(t, err)
	assert.Equal(t, conventions.SchemaURL, schemaURL)
	mp.AssertExpectations(t)

	expected := map[string]any{
		conventions.AttributeCloudProvider:  conventions.AttributeCloudProviderAzure,
		conventions.AttributeCloudPlatform:  conventions.AttributeCloudPlatformAzureVM,
		conventions.AttributeHostName:       "name",
		conventions.AttributeCloudRegion:    "location",
		conventions.AttributeHostID:         "vmID",
		conventions.AttributeCloudAccountID: "subscriptionID",
		"azure.vm.name":                     "name",
		"azure.vm.size":                     "vmSize",
		"azure.resourcegroup.name":          "resourceGroup",
		"azure.vm.scaleset.name":            "myScaleset",
	}

	assert.Equal(t, expected, res.Attributes().AsRaw())
}

func TestDetectError(t *testing.T) {
	mp := &azure.MockProvider{}
	mp.On("Metadata").Return(&azure.ComputeMetadata{}, fmt.Errorf("mock error"))
	detector := &Detector{
		provider: mp,
		logger:   zap.NewNop(),
		rb:       metadata.NewResourceBuilder(metadata.DefaultResourceAttributesConfig()),
	}
	res, _, err := detector.Detect(context.Background())
	assert.NoError(t, err)
	assert.True(t, internal.IsEmptyResource(res))
}
