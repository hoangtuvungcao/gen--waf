package observability

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MetricsSnapshot represents current operational metrics
type MetricsSnapshot struct {
	// Data plane metrics
	TotalRequests       uint64
	BlockedRequests     uint64
	ChallengedRequests  uint64
	RateLimitedRequests uint64
	ShedConnections     uint64
	CacheHits           uint64
	CacheMisses         uint64
	HealthyBackends     int
	UnhealthyBackends   int
	SharedDecisions     uint64
	PressuredClients    int

	// Controller metrics (multi-node)
	RegisteredNodes      int
	NodeHeartbeatTimeout time.Duration
	ActiveObservations   int
	DecisionsPropagated  uint64

	// Redis sync metrics
	RedisSyncLag      time.Duration
	RedisConnectionOK bool
	LastRedisSyncTime time.Time

	// Rate limiter state
	TrackedIPCount  int
	MaxTrackedIPs   int
	TokenRefillRate float64

	// Challenge/Block state
	ActiveChallengeTokens int
	MaxChallengeTokens    int
}

// PrometheusExporter converts metrics to Prometheus format
type PrometheusExporter struct {
	mu         sync.RWMutex
	snapshot   MetricsSnapshot
	lastUpdate time.Time
}

// NewPrometheusExporter creates a new exporter
func NewPrometheusExporter() *PrometheusExporter {
	return &PrometheusExporter{
		lastUpdate: time.Now(),
	}
}

// UpdateMetrics updates the snapshot
func (pe *PrometheusExporter) UpdateMetrics(snapshot MetricsSnapshot) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.snapshot = snapshot
	pe.lastUpdate = time.Now()
}

// FormatPrometheus returns metrics in Prometheus text format
func (pe *PrometheusExporter) FormatPrometheus() string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	output := `# HELP genwaf_requests_total Total requests processed
# TYPE genwaf_requests_total counter
genwaf_requests_total{status="all"} %d
genwaf_requests_total{status="blocked"} %d
genwaf_requests_total{status="challenged"} %d
genwaf_requests_total{status="rate_limited"} %d
genwaf_requests_total{status="shed"} %d

# HELP genwaf_cache_hits Cache hits
# TYPE genwaf_cache_hits counter
genwaf_cache_hits %d

# HELP genwaf_cache_misses Cache misses
# TYPE genwaf_cache_misses counter
genwaf_cache_misses %d

# HELP genwaf_backends_healthy Healthy backends count
# TYPE genwaf_backends_healthy gauge
genwaf_backends_healthy %d

# HELP genwaf_backends_unhealthy Unhealthy backends count
# TYPE genwaf_backends_unhealthy gauge
genwaf_backends_unhealthy %d

# HELP genwaf_shared_decisions Shared decisions count
# TYPE genwaf_shared_decisions counter
genwaf_shared_decisions %d

# HELP genwaf_pressured_clients Pressured clients count
# TYPE genwaf_pressured_clients gauge
genwaf_pressured_clients %d

# HELP genwaf_registered_nodes Registered nodes in cluster
# TYPE genwaf_registered_nodes gauge
genwaf_registered_nodes %d

# HELP genwaf_active_observations Active observations from nodes
# TYPE genwaf_active_observations gauge
genwaf_active_observations %d

# HELP genwaf_decisions_propagated Decisions propagated to nodes
# TYPE genwaf_decisions_propagated counter
genwaf_decisions_propagated %d

# HELP genwaf_redis_sync_lag_ms Redis sync lag in milliseconds
# TYPE genwaf_redis_sync_lag_ms gauge
genwaf_redis_sync_lag_ms %d

# HELP genwaf_redis_connection_ok Redis connection status (1=ok, 0=fail)
# TYPE genwaf_redis_connection_ok gauge
genwaf_redis_connection_ok %d

# HELP genwaf_tracked_ips Tracked IP count for rate limiting
# TYPE genwaf_tracked_ips gauge
genwaf_tracked_ips{type="current"} %d
genwaf_tracked_ips{type="max"} %d

# HELP genwaf_rate_limit_refill_rate Token refill rate per second
# TYPE genwaf_rate_limit_refill_rate gauge
genwaf_rate_limit_refill_rate %.2f

# HELP genwaf_active_challenge_tokens Active challenge tokens
# TYPE genwaf_active_challenge_tokens gauge
genwaf_active_challenge_tokens{type="current"} %d
genwaf_active_challenge_tokens{type="max"} %d

# HELP genwaf_metrics_update_time_seconds Last metrics update timestamp
# TYPE genwaf_metrics_update_time_seconds gauge
genwaf_metrics_update_time_seconds %.0f
`

	redisOK := 0
	if pe.snapshot.RedisConnectionOK {
		redisOK = 1
	}

	return fmt.Sprintf(output,
		pe.snapshot.TotalRequests,
		pe.snapshot.BlockedRequests,
		pe.snapshot.ChallengedRequests,
		pe.snapshot.RateLimitedRequests,
		pe.snapshot.ShedConnections,
		pe.snapshot.CacheHits,
		pe.snapshot.CacheMisses,
		pe.snapshot.HealthyBackends,
		pe.snapshot.UnhealthyBackends,
		pe.snapshot.SharedDecisions,
		pe.snapshot.PressuredClients,
		pe.snapshot.RegisteredNodes,
		pe.snapshot.ActiveObservations,
		pe.snapshot.DecisionsPropagated,
		pe.snapshot.RedisSyncLag.Milliseconds(),
		redisOK,
		pe.snapshot.TrackedIPCount,
		pe.snapshot.MaxTrackedIPs,
		pe.snapshot.TokenRefillRate,
		pe.snapshot.ActiveChallengeTokens,
		pe.snapshot.MaxChallengeTokens,
		float64(pe.lastUpdate.Unix()),
	)
}

// HTTPHandler returns an HTTP handler for serving Prometheus metrics
func (pe *PrometheusExporter) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, pe.FormatPrometheus())
	}
}
