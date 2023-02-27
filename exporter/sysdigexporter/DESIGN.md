

# **OpenTelemetry Collector Sysdig Remote Write Exporter Design**

Authors: @mms2409

Date: February 20, 2023

## **1. Introduction**

Prometheus can be integrated with remote storage systems that supports its remote write API. Existing remote storage integration support is included in [Sysdig](https://sysdig.com/opensource/prometheus/).

### **1.1 Remote Write API**

The Sysdig exporter should write metrics to a remote URL in a snappy-compressed, [protocol buffer](https://github.com/prometheus/prometheus/blob/master/prompb/remote.proto#L22) encoded HTTP request defined by the Prometheus remote write API. A request should encode multiple Prometheus remote write TimeSeries (set of labels and a collection of samples) or Metadata (type, family name and unit of the metric). Each label contains a name-value pair of strings, and each sample contains a timestamp-value number pair. The supported metric types are gauges, delta counters, cumulative counters, histograms, and summary. Non-cumulative histograms and summary are not supported yet.

```
type TimeSeries struct {
    Labels               []Label
    Samples              []Sample
    Exemplars            []Exemplar
    Histograms           []Histogram 
}
```

```
type MetricMetadata struct {
    Type                 MetricMetadata_MetricType
    MetricFamilyName     string
    Help                 string
    Unit                 string
}
```

TimeSeries stores its metric name in its labels and does not describe metric types or start timestamps. To convert to TimeSeries data, buckets of a Histogram are broken down into individual TimeSeries with a bound label(`le`), and a similar process happens with quantiles in a Summary.


More details of Prometheus remote write API can be found in Prometheus [documentation](https://prometheus.io/docs/prometheus/latest/storage/#overview).

### **1.2 Gaps and Assumptions**

**Gap 1:**
Currently, metrics from the OpenTelemetry SDKs cannot be exported to Prometheus from the collector correctly ([#1255](https://github.com/open-telemetry/opentelemetry-collector/issues/1255)). This is because the SDKs send metrics to the collector via their OTLP exporter, which exports the delta value of cumulative counters. This will not be an issue in case of delta counters since Sysdig adds metadata to detect if it is a delta counter or a cumulative one. In case of non-cumulative historgrams and summaries, those metrics will be dropped. We are working on making those work as well.

**Gap 2:**
Another gap is that OTLP metric definition is still in development. This exporter will require refactoring as OTLP changes in the future.

**Assumptions:**
Because of the gaps mentioned above, this project will convert from the current OTLP metrics and work under the assumption one of the above solutions will be implemented, and all incoming monotonic histogram/summary metrics should be cumulative or otherwise dropped. Scalars are an exception to this rule. More details on the behavior of the exporter is in section 2.2.

## **2. Sysdig Remote Write Exporter**

The Sysdig remote write exporter should receive  OTLP metrics, group data points by metric name and label set, convert each group to a TimeSeries, and send all TimeSeries to a storage backend via HTTP. It also adds support for metadata generation which is sent along with the timeseries as a separate request.

### **2.1 Receiving Metrics**
The Sysdig remote write exporter receives a Metrics instance in its PushMetrics() function. Metrics contains a collection of Metric instances. Each Metric instance contains a series of data points, and each data point has a set of labels associated with it. Since Prometheus remote write TimeSeries are identified by unique sets of labels, the exporter needs to group data points within each Metric instance by their label set, and convert each group to a TimeSeries. In addition, this exporter also batches associated metadata. This is useful when dealing with non-cumulative scalars.

To group data points by label set, the exporter should create two maps with each PushMetrics() call. The key of the maps should represent a combination of the following information:

* the metric type
* the metric name
* the set of labels that identify a unique TimeSeries


The exporter should create a signature string as map key by concatenating metric type, metric name, and label names and label values at each data point. To ensure correctness, the label set at each data point should be sorted by label key before generating the signature string.  

An alternative key type is in the exiting label.Set implementation from the OpenTelemetry Go API. It provides a Distinct type that guarantees the result will equal the equivalent Distinct value of any label set with the same elements as this,  where sets are made unique by choosing the last value in the input for any given key. If we allocate a Go API's kv.KeyValue for every label of a data point, then a label.Set from the API can be created, and its Distinct value can be used as map key.


The value of the first map should be Prometheus TimeSeries, and each data point’s value and timestamp should be inserted to its corresponding TimeSeries in the map as a Sample, each metric’s label set and metric name should be combined and translated to a Prometheus label set; a new TimeSeries should be created if the string signature is not in the map.

The value of the second map is the metadata (instance of MetricMetadata). Each metadata is populated with the fields like metric family name, type, and unit. In case of delta counters, the unit field is prefixed with "delta_counter:" to indicate that the incoming scalar is non-cumulative.

### **2.2 Mapping of OTLP Metrics to TimeSeries**

Each Prometheus remote write TimeSeries represents less semantic information than an OTLP metric. The temporality property of a OTLP metric is ignored in a TimeSeries for histogram and summary, because it is always considered as cumulative. This is not true for counters as both cumulative and delta are supported by Sysdig exporter. The type property of a OTLP metric is translated by mapping each metric to one or multiple TimeSeries. Metadata is associated with every Timeseries as a separate remote write request. The following sections explain how to map each OTLP metric type to Prometheus remote write TimeSeries.


**INT64, MONOTONIC_INT64, DOUBLE, MONOTONIC_DOUBLE**

Each unique label set within metrics of these types can be converted to exactly one TimeSeries. From the perspective of Prometheus client types, INT64 and DOUBLE correspond to gauge metrics, and MONOTONIC types correspond to counter metrics. In both cases, data points will be exported directly without aggregation. Any metric of the monotonic types that is not cumulative will be have a "delta_counter:" prefix for identification; non-monotonic scalar types are assumed to represent gauge values. Monotonic types need to have a `_total` suffix in its metric name when exporting; this is a requirement of Prometheus.

**HISTOGRAM**

Each histogram data point can be converted to 2 + n + 1 Prometheus remote write TimeSeries:

* 1 *TimeSeries* representing metric_name_count contains HistogramDataPoint.count
* 1 *TimeSeries* representing metric_name_sum contains HistogramDataPoint.sum
* n *TimeSeries* each representing metric_name_bucket{le=“upperbound”} contain the count of each bucket defined by the bounds of the data point
* 1 *TimeSeries* representing metric_name_bucket{le=“+Inf”} contains counts for the bucket with infinity as upper bound; its value is equivalent to metric_name_count.

Prometheus bucket values are cumulative, meaning the count of each bucket should contain counts from buckets with lower bounds. In addition, Exemplars from a histogram data point are ignored. When adding a bucket of the histogram data point to the map, the string signature should also contain a `le` label that indicates the bound value. This label should also be exported. Any histogram metric that is not cumulative should be dropped.


**SUMMARY**

Each summary data point can be converted to 2 + n Prometheus remote write TimeSeries:

* 1 *TimeSeries* representing metric_name_count contains SummaryDataPoint.count
* 1 *TimeSeries* representing metric_name_sum contains SummaryDataPoint.sum
* and n *TimeSeries* each representing metric_name{quantile=“quantileValue”} contains the value of each quantile in the data point.

When adding a quantile of the summary data point to the map, the string signature should also contain a `quantile ` label that indicates the quantile value. This label should also be exported. Any summary metric that is not cumulative should be dropped.

### **2.3 Exporting Metrics**

The Sysdig remote write exporter should call proto.Marshal() to convert multiple TimeSeries to a byte array. The same goes for multiple metadata requests. Then, the exporter should send the byte array to Prometheus remote storage in a HTTP request.


Authentication credentials (Bearer token) should be added to each request before sending to the backend.

## **3. Other Components**

### **3.1 Config Struct**

This struct is based on an inputted YAML file at the beginning of the pipeline and defines the configurations for an Exporter build. Examples of configuration parameters are HTTP endpoint, compression type, backend program, etc.


Converting YAML to a Go struct is done by the Collector, using [_the Viper package_](https://github.com/spf13/viper), which is an open-source library that seamlessly converts inputted YAML files into a usable, appropriate Config struct.


An example of the exporter section of the Collector config.yml YAML file can be seen below:

    ...

    exporters:
      sysdig:
        endpoint: <string>
        bearer_token: <string>
        # Prefix to metric name
        namespace: <string>
        # Labels to add to each TimeSeries
        external_labels:
            [label: <string>]
        # Allow users to add any header; only required headers listed here
        headers:
            [X-Prometheus-Remote-Write-Version:<string>]
        request_timeout: <int>

        # ************************************************************************
        # below are configurations copied from Sysdig remote write config   
        # ************************************************************************
        # Sets the `Authorization` header on every remote write request with
        # the configured bearer token. It is mutually exclusive with `bearer_token_file`.
        [ bearer_token: <string> ]

        # Configures the remote write request's TLS settings.
        tls_config:
            # CA certificate to validate API server certificate with.
            [ ca_file: <filename> ]

            # Certificate and key files for client cert authentication to the server.
            [ cert_file: <filename> ]
            [ key_file: <filename> ]

            # ServerName extension to indicate the name of the server.
            # https://tools.ietf.org/html/rfc4366#section-3.1
            [ server_name: <string> ]

            # Disable validation of the server certificate.
            [ insecure_skip_verify: <boolean> ]

    ...

### **3.2 Factory Struct**

This struct implements the ExporterFactory interface, and is used during collector’s pipeline initialization to create the Exporter instances as defined by the Config struct. The `exporterhelper` package will be used to create the exporter and the factory.


Our Factory type will look very similar to other exporters’ factory implementation. For our implementation, our Factory instance will implement three methods


**Methods**

    NewFactory
This method will use the NewFactory method within the `exporterhelper` package to create a instance of the factory.

    createDefaultConfig

This method creates the default configuration for Sysdig remote write exporter.


    createMetricsExporter

This method constructs a new http.Client with interceptors that add headers to any request it sends. Then, this method initializes a new Sysdig remote write exporter with the http.Client. This method constructs a collector Sysdig exporter with the created SDK exporter 



## **4. Other Considerations**

### **4.1 Concurrency**

The Sysdig remote write should be thread-safe; In this design, the only resource shared across goroutines is the http.Client from the Golang library. It is thread-safe, thus, our code is thread-safe. 

### **4.2 Shutdown Behavior**

Once the shutdown() function is called, the exporter should stop accepting incoming calls(return error), and wait for current operations to finish before returning. This can be done by using a stop channel and a wait group.

    func Shutdown () {
        close(stopChan)
        waitGroup.Wait()
    }

    func PushMetrics() {
	    select:
	        case <- stopCh
	               return error
	        default:
	               waitGroup.Add(1)
	               defer waitGroup.Done()
	               // export metrics
		  ...
    }

### **4.3 Timeout Behavior**

Users should be able to pass in a time for the each http request as part of the Configuration. The factory should read the configuration file and set the timeout field of the http.Client

    func (f *Factory) CreateNewExporter (config) {
    ...
        client := &http.Client{
                Timeout config.requestTimeout
        }
    ...
    }

### **4.4 Error Behavior**

The PushMetricsData() function should return the number of dropped metrics. Any histogram and summary metrics that are not cumulative should be dropped. This will not be the case for non-cumulative scalars. This can be done by checking the temporality of each received metric. Any error should be returned to the caller, and the error message should be descriptive. 



### **4.5 Test Strategy**

We will follow test-driven development practices while completing this project. We’ll write unit tests before implementing production code. Tests will cover normal and abnormal inputs and test for edge cases. We will provide end-to-end tests using mock backend/client. Our target is to get 90% or more of code coverage.



## **Request for Feedback**
We'd like to get some feedback on whether we made the appropriate assumptions in [this](#12-gaps-and-assumptions) section, and appreciate more comments, updates , and suggestions on the topic.

Please let us know if there are any revisions, technical or informational, necessary for this document. Thank you!



