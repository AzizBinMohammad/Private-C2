package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "privatec2_active_sessions",
		Help: "Number of active implant sessions",
	})
	ActiveBeacons = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "privatec2_active_beacons",
		Help: "Number of active beacons",
	})
	ActiveListeners = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "privatec2_active_listeners",
		Help: "Number of active listeners",
	})
	GRPCRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "privatec2_grpc_requests_total",
		Help: "Total gRPC requests by method and status",
	}, []string{"method", "code"})
	GRPCRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "privatec2_grpc_request_duration_seconds",
		Help:    "gRPC request latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"method"})
	TasksExecuted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "privatec2_tasks_executed_total",
		Help: "Total tasks executed by type and status",
	}, []string{"type", "status"})
	PayloadsBuilt = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "privatec2_payloads_built_total",
		Help: "Total payloads built",
	})
	DataExfilBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "privatec2_data_exfil_bytes_total",
		Help: "Total bytes exfiltrated by engagement",
	}, []string{"engagement_id"})
	ScopeViolations = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "privatec2_scope_violations_total",
		Help: "Total scope violation attempts blocked",
	})
	KillSwitchActivations = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "privatec2_killswitch_activations_total",
		Help: "Total kill switch activations",
	})
)

func Init() {
	prometheus.MustRegister(
		ActiveSessions,
		ActiveBeacons,
		ActiveListeners,
		GRPCRequestsTotal,
		GRPCRequestDuration,
		TasksExecuted,
		PayloadsBuilt,
		DataExfilBytes,
		ScopeViolations,
		KillSwitchActivations,
	)
}

func Handler() http.Handler {
	return promhttp.Handler()
}
