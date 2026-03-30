package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"genwaf/internal/config"
	"genwaf/internal/controller"
	"genwaf/internal/policy"
	"genwaf/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "compile":
		compile(os.Args[2:])
	case "validate":
		validate(os.Args[2:])
	case "simulate":
		simulate(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "configs/genwaf.example.yaml", "path to declarative config")
	listenAddr := fs.String("listen", ":8080", "HTTP listen address")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctrl := controller.New(cfg)
	srv := server.New(ctrl)
	log.Printf("genctl listening on %s with mode=%s", *listenAddr, cfg.System.Mode)
	if err := http.ListenAndServe(*listenAddr, srv.Handler()); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func compile(args []string) {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	configPath := fs.String("config", "configs/genwaf.example.yaml", "path to declarative config")
	modeOverride := fs.String("mode", "", "override mode for compilation")
	outputPath := fs.String("output", "", "optional path to write effective config JSON")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	effective := policy.Compile(cfg, chooseMode(cfg.System.Mode, *modeOverride))
	if *outputPath != "" {
		if err := writeJSONFile(*outputPath, effective); err != nil {
			log.Fatalf("write effective config: %v", err)
		}
	}

	printJSON(effective)
}

func validate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "configs/genwaf.example.yaml", "path to declarative config")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("validate config: %v", err)
	}

	poolCount, backendCount, hostCount, domainCount, pathRuleCount := routingStats(cfg)
	summary := map[string]any{
		"status":              "ok",
		"name":                cfg.System.Name,
		"deployment":          cfg.System.Deployment,
		"mode":                cfg.System.Mode,
		"proxy_engine":        cfg.Origin.Proxy.Engine,
		"listen_port":         cfg.Origin.Proxy.ListenPort,
		"xdp_interface":       cfg.Origin.XDP.Interface,
		"xdp_attach_mode":     cfg.Origin.XDP.AttachMode,
		"xdp_allowlist_cidrs": cfg.Origin.XDP.AllowlistCIDRs,
		"cloudflare_enabled":  cfg.Edge.Cloudflare.Enabled,
		"edge_model":          edgeModel(cfg),
		"waf_engine":          cfg.WAF.Engine,
		"xdp_enabled":         cfg.Origin.XDP.Enabled,
		"auto_mode":           cfg.System.AutoMode,
		"cluster_sync":        cfg.Cluster.SyncEnabled,
		"sync_backend":        cfg.Cluster.SyncBackend,
		"zero_touch":          cfg.Implementation.ZeroTouchBootstrap,
		"sensitive_paths":     cfg.RateLimit.SensitivePaths,
		"cluster_runtime": map[string]any{
			"shared_decisions":                cfg.Cluster.SharedDecisions,
			"shared_decision_ttl_seconds":     cfg.Cluster.SharedDecisionTTLSeconds,
			"local_decision_path":             cfg.Cluster.LocalDecisionPath,
			"local_observation_path":          cfg.Cluster.LocalObservationPath,
			"shared_rate_limit_path":          cfg.Cluster.SharedRateLimitPath,
			"decision_poll_interval_ms":       cfg.Cluster.DecisionPollIntervalMS,
			"observation_flush_interval_ms":   cfg.Cluster.ObservationFlushIntervalMS,
			"observation_window_seconds":      cfg.Cluster.ObservationWindowSeconds,
			"shared_rate_limit_threshold":     cfg.Cluster.SharedRateLimitThreshold,
			"shared_challenge_threshold":      cfg.Cluster.SharedChallengeThreshold,
			"node_heartbeat_interval_seconds": cfg.Cluster.NodeHeartbeatIntervalSeconds,
			"controller_state_path":           cfg.Cluster.ControllerStatePath,
		},
		"parser_guards": map[string]any{
			"max_active_connections":     cfg.Origin.Proxy.MaxActiveConnections,
			"max_keepalive_requests":     cfg.Origin.Proxy.MaxKeepaliveRequests,
			"header_read_timeout_ms":     cfg.Origin.Proxy.HeaderReadTimeoutMS,
			"max_request_bytes":          cfg.Origin.Proxy.MaxRequestBytes,
			"max_response_cache_entries": cfg.Origin.Proxy.MaxResponseCacheEntries,
		},
		"state_limits": map[string]any{
			"rate_limit_max_tracked_ips":    cfg.RateLimit.MaxTrackedIPs,
			"max_decision_entries":          cfg.Behavior.MaxDecisionEntries,
			"challenge_difficulty":          cfg.BotDefense.ChallengeDifficulty,
			"challenge_token_cache_entries": cfg.BotDefense.ChallengeTokenCacheEntries,
			"challenge_pass_ttl_seconds":    cfg.BotDefense.ChallengePassTTLSeconds,
			"challenge_replay_protection":   cfg.BotDefense.ReplayProtection,
		},
		"storage": map[string]any{
			"redis_enabled":    cfg.Storage.RedisEnabled,
			"redis_address":    cfg.Storage.RedisAddress,
			"redis_prefix":     cfg.Storage.RedisPrefix,
			"postgres_enabled": cfg.Storage.PostgresEnabled,
		},
		"observability": map[string]any{
			"metrics":   cfg.Observability.Metrics,
			"logs":      cfg.Observability.Logs,
			"traces":    cfg.Observability.Traces,
			"dashboard": cfg.Observability.Dashboard,
		},
		"routing": map[string]any{
			"backend_pools":  poolCount,
			"backend_nodes":  backendCount,
			"virtual_hosts":  hostCount,
			"domains":        domainCount,
			"path_rules":     pathRuleCount,
			"balancers":      supportedBalancers(cfg),
			"catch_all_host": hasCatchAllHost(cfg),
		},
		"supported_runtime_features": []string{
			"cloudflare-origin-lock",
			"reverse-proxy-routing",
			"round-robin-balance",
			"ip-hash-balance",
			"request-body-forwarding",
			"upstream-timeouts",
			"token-bucket-rate-limit",
			"waf-runtime",
			"challenge-routing",
			"challenge-replay-protection",
			"progressive-local-challenge-ladder",
			"http-browser-fingerprinting",
			"edge-tls-fingerprint-ingest",
			"edge-gateway-h1-h2-h3",
			"fingerprint-reputation-and-fanout-escalation",
			"connection-shedding",
			"controller-backed-shared-decisions",
			"controller-backed-shared-observations",
			"redis-backed-cluster-reputation",
			"shared-rate-pressure-sync",
			"redis-native-data-plane-rate-limit",
			"multi-node-practical-escalation",
			"node-heartbeat-and-rollout-ack",
			"xdp-profile-compile",
			"xdp-ipv4-allowlist",
			"xdp-live-stats-watch",
			"xdp-controller-sync",
			"operator-dashboard",
		},
	}
	printJSON(summary)
}

func simulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	configPath := fs.String("config", "configs/genwaf.example.yaml", "path to declarative config")
	metricsPath := fs.String("metrics-file", "", "optional path to metrics JSON file")
	metricsRaw := fs.String("metrics-json", "", "inline metrics JSON payload")
	apply := fs.Bool("apply", false, "apply the simulated metrics to controller state")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	metrics, err := loadMetrics(*metricsPath, *metricsRaw)
	if err != nil {
		log.Fatalf("load metrics: %v", err)
	}

	ctrl := controller.New(cfg)
	var snapshot controller.Snapshot
	if *apply {
		snapshot = ctrl.Evaluate(metrics)
	} else {
		snapshot = ctrl.Simulate(metrics)
	}
	printJSON(snapshot)
}

func loadMetrics(path, raw string) (policy.ObservedMetrics, error) {
	switch {
	case raw != "":
		var metrics policy.ObservedMetrics
		if err := json.Unmarshal([]byte(raw), &metrics); err != nil {
			return policy.ObservedMetrics{}, fmt.Errorf("parse inline metrics: %w", err)
		}
		return metrics, nil
	case path != "":
		body, err := os.ReadFile(path)
		if err != nil {
			return policy.ObservedMetrics{}, fmt.Errorf("read metrics file: %w", err)
		}
		var metrics policy.ObservedMetrics
		if err := json.Unmarshal(body, &metrics); err != nil {
			return policy.ObservedMetrics{}, fmt.Errorf("parse metrics file: %w", err)
		}
		return metrics, nil
	default:
		return policy.ObservedMetrics{}, fmt.Errorf("either -metrics-file or -metrics-json is required")
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <serve|compile|validate|simulate> [flags]\n", filepath.Base(os.Args[0]))
}

func routingStats(cfg config.Config) (int, int, int, int, int) {
	poolCount := len(cfg.Routing.BackendPools)
	hostCount := len(cfg.Routing.VirtualHosts)
	backendCount := 0
	domainCount := 0
	pathRuleCount := 0
	for _, pool := range cfg.Routing.BackendPools {
		backendCount += len(pool.Servers)
	}
	for _, host := range cfg.Routing.VirtualHosts {
		domainCount += len(host.Domains)
		pathRuleCount += len(host.PathRules)
	}
	return poolCount, backendCount, hostCount, domainCount, pathRuleCount
}

func supportedBalancers(cfg config.Config) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, pool := range cfg.Routing.BackendPools {
		if _, ok := seen[pool.Balance]; ok {
			continue
		}
		seen[pool.Balance] = struct{}{}
		out = append(out, pool.Balance)
	}
	return out
}

func hasCatchAllHost(cfg config.Config) bool {
	for _, host := range cfg.Routing.VirtualHosts {
		for _, domain := range host.Domains {
			if domain == "*" {
				return true
			}
		}
	}
	return false
}

func edgeModel(cfg config.Config) string {
	if cfg.Edge.Cloudflare.Enabled && cfg.Origin.Proxy.ListenPort == 80 {
		return "cloudflare-flexible-http-origin"
	}
	if cfg.Edge.Cloudflare.Enabled {
		return "cloudflare-proxied-origin"
	}
	return "direct-origin"
}

func chooseMode(current, override string) string {
	if override != "" {
		return override
	}
	return current
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encode json: %v", err)
	}
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir effective path: %w", err)
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal effective config: %w", err)
	}
	return os.WriteFile(path, raw, 0o644)
}
