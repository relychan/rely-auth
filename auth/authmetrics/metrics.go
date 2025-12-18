// Package authmetrics defines global metrics and attributes for the auth service.
package authmetrics

import (
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// RelyAuthMetrics hold semantic metrics of the rely-auth service.
type RelyAuthMetrics struct {
	// Total number of successful auth mode requests.
	AuthModeTotalRequests metric.Int64Counter
	// Duration of authentication requests.
	RequestDuration metric.Float64Histogram
}

// NewRelyAuthMetrics creates a [RelyAuthMetrics] instance from the OpenTelemetry meter.
func NewRelyAuthMetrics(meter metric.Meter) (*RelyAuthMetrics, error) {
	var err error

	metrics := &RelyAuthMetrics{}

	metrics.RequestDuration, err = meter.Float64Histogram(
		"rely_auth.request.duration",
		metric.WithDescription("Duration of authentication requests."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.005,
			0.01,
			0.025,
			0.05,
			0.075,
			0.1,
			0.25,
			0.5,
			0.75,
			1,
			2.5,
			5,
			7.5,
			10,
		),
	)
	if err != nil {
		return nil, err
	}

	metrics.AuthModeTotalRequests, err = meter.Int64Counter(
		"rely_auth.request_mode.total",
		metric.WithDescription("Total number of successful auth mode requests."),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

var globalAuthMetrics = defaultAuthMetrics()

// GetRelyAuthMetrics gets the global [RelyAuthMetrics] instance.
func GetRelyAuthMetrics() *RelyAuthMetrics {
	return globalAuthMetrics.Load()
}

// SetRelyAuthMetrics sets the global [RelyAuthMetrics] instance.
func SetRelyAuthMetrics(metrics *RelyAuthMetrics) {
	if metrics == nil {
		metrics = &noopRelyAuthMetrics
	}

	globalAuthMetrics.Store(metrics)
}

var noopRelyAuthMetrics = RelyAuthMetrics{
	AuthModeTotalRequests: noop.Int64Counter{},
	RequestDuration:       noop.Float64Histogram{},
}

func defaultAuthMetrics() *atomic.Pointer[RelyAuthMetrics] {
	value := atomic.Pointer[RelyAuthMetrics]{}

	value.Store(&noopRelyAuthMetrics)

	return &value
}
