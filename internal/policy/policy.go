package policy

import (
	"strconv"
	"time"

	"genwaf/internal/config"
	"genwaf/internal/hostprofile"
)

type ObservedMetrics struct {
	RPSMultiplier      float64 `json:"rps_multiplier"`
	Error4xxRatio      float64 `json:"error_4xx_ratio"`
	WAFHitsPerMin      int     `json:"waf_hits_per_min"`
	ChallengeFailRatio float64 `json:"challenge_fail_ratio"`
	CPUPercent         float64 `json:"cpu_percent"`
	DirectOriginHits   int     `json:"direct_origin_hits"`
	ConnectionBacklog  int     `json:"connection_backlog"`
	FingerprintBursts  int     `json:"fingerprint_bursts"`
	FingerprintFanout  int     `json:"fingerprint_fanout"`
}

type EffectiveConfig struct {
	Name                       string    `json:"name"`
	Deployment                 string    `json:"deployment"`
	Mode                       string    `json:"mode"`
	GeneratedAt                time.Time `json:"generated_at"`
	AutoMode                   bool      `json:"auto_mode"`
	ControlPlaneLang           string    `json:"control_plane_lang"`
	DataPlaneLang              string    `json:"data_plane_lang"`
	NodeAgentLang              string    `json:"node_agent_lang"`
	XDPManagerLang             string    `json:"xdp_manager_lang"`
	ConfigModel                string    `json:"config_model"`
	ProxyEngine                string    `json:"proxy_engine"`
	ListenPort                 int       `json:"listen_port"`
	CloudflareEnabled          bool      `json:"cloudflare_enabled"`
	ProxyDNS                   bool      `json:"proxy_dns"`
	HideOriginIP               bool      `json:"hide_origin_ip"`
	LockOriginToCF             bool      `json:"lock_origin_to_cf"`
	CacheStatic                bool      `json:"cache_static"`
	TrustCFHeaders             bool      `json:"trust_cf_headers"`
	XDPEnabled                 bool      `json:"xdp_enabled"`
	XDPMode                    string    `json:"xdp_mode"`
	XDPInterface               string    `json:"xdp_interface"`
	XDPAttachMode              string    `json:"xdp_attach_mode"`
	XDPSyncFromController      bool      `json:"xdp_sync_from_controller"`
	AllowCFOnly                bool      `json:"allow_cf_only"`
	XDPAllowlistCIDRs          []string  `json:"xdp_allowlist_cidrs"`
	DropInvalidPackets         bool      `json:"drop_invalid_packets"`
	PerIPGuard                 bool      `json:"per_ip_guard"`
	RealIPFromEdgeOnly         bool      `json:"real_ip_from_edge_only"`
	CacheEnabled               bool      `json:"cache_enabled"`
	Keepalive                  bool      `json:"keepalive"`
	HTTPParser                 string    `json:"http_parser"`
	WorkerModel                string    `json:"worker_model"`
	WorkerThreads              int       `json:"worker_threads"`
	MaxActiveConnections       int       `json:"max_active_connections"`
	MaxKeepaliveRequests       int       `json:"max_keepalive_requests"`
	HeaderReadTimeoutMS        int       `json:"header_read_timeout_ms"`
	MaxRequestBytes            int       `json:"max_request_bytes"`
	MaxResponseCacheEntries    int       `json:"max_response_cache_entries"`
	UpstreamConnectTimeoutMS   int       `json:"upstream_connect_timeout_ms"`
	UpstreamReadTimeoutMS      int       `json:"upstream_read_timeout_ms"`
	WAFEnabled                 bool      `json:"waf_enabled"`
	WAFEngine                  string    `json:"waf_engine"`
	WAFMode                    string    `json:"waf_mode"`
	WAFParanoiaLevel           int       `json:"waf_paranoia_level"`
	WAFRuleset                 string    `json:"waf_ruleset"`
	CRSImportEnabled           bool      `json:"crs_import_enabled"`
	RateLimitEnabled           bool      `json:"rate_limit_enabled"`
	RateLimitBackend           string    `json:"rate_limit_backend"`
	RateLimitRPS               int       `json:"rate_limit_rps"`
	RateLimitBurst             int       `json:"rate_limit_burst"`
	RateLimitMaxTrackedIPs     int       `json:"rate_limit_max_tracked_ips"`
	SensitivePaths             []string  `json:"sensitive_paths"`
	BotDefenseEnabled          bool      `json:"bot_defense_enabled"`
	DefaultAction              string    `json:"default_action"`
	JSChallenge                bool      `json:"js_challenge"`
	ReplayProtection           bool      `json:"replay_protection"`
	ChallengeDifficulty        int       `json:"challenge_difficulty"`
	ChallengeTokenCacheEntries int       `json:"challenge_token_cache_entries"`
	ChallengePassTTLSeconds    int       `json:"challenge_pass_ttl_seconds"`
	POWEnabled                 bool      `json:"pow_enabled"`
	POWProvider                string    `json:"pow_provider"`
	ChallengeScope             string    `json:"challenge_scope"`
	BehaviorEnabled            bool      `json:"behavior_enabled"`
	BehaviorEngine             string    `json:"behavior_engine"`
	DecisionCacheTTL           string    `json:"decision_cache_ttl"`
	MaxDecisionEntries         int       `json:"max_decision_entries"`
	ReputationEnabled          bool      `json:"reputation_enabled"`
	LearnBaseline              bool      `json:"learn_baseline"`
	FingerprintTLS             bool      `json:"fingerprint_tls"`
	FingerprintHTTP            bool      `json:"fingerprint_http"`
	FingerprintCookie          bool      `json:"fingerprint_cookie"`
	FingerprintSession         bool      `json:"fingerprint_session"`
	ResponseAction             string    `json:"response_action"`
	CacheAggressive            bool      `json:"cache_aggressive"`
	SitewideChallenge          bool      `json:"sitewide_challenge"`
	ZeroTouchBootstrap         bool      `json:"zero_touch_bootstrap"`
	AutoTuneFromHost           bool      `json:"auto_tune_from_host"`
	CooldownMinutes            int       `json:"cooldown_minutes"`
	ClusterSyncEnabled         bool      `json:"cluster_sync_enabled"`
	SyncBackend                string    `json:"sync_backend"`
	ConfigPushEnabled          bool      `json:"config_push_enabled"`
	ConfigVersioning           bool      `json:"config_versioning"`
	StagedRollout              bool      `json:"staged_rollout"`
	SharedDecisions            bool      `json:"shared_decisions"`
	SharedDecisionTTLSeconds   int       `json:"shared_decision_ttl_seconds"`
	LocalDecisionPath          string    `json:"local_decision_path"`
	LocalObservationPath       string    `json:"local_observation_path"`
	SharedRateLimitPath        string    `json:"shared_rate_limit_path"`
	DecisionPollIntervalMS     int       `json:"decision_poll_interval_ms"`
	ObservationFlushInterval   int       `json:"observation_flush_interval_ms"`
	ObservationWindowSeconds   int       `json:"observation_window_seconds"`
	SharedRateLimitThreshold   int       `json:"shared_rate_limit_threshold"`
	SharedChallengeThreshold   int       `json:"shared_challenge_threshold"`
	NodeHeartbeatInterval      int       `json:"node_heartbeat_interval_seconds"`
	RedisEnabled               bool      `json:"redis_enabled"`
	RedisAddress               string    `json:"redis_address"`
	RedisPassword              string    `json:"redis_password"`
	RedisDB                    int       `json:"redis_db"`
	RedisPrefix                string    `json:"redis_prefix"`
	PostgresEnabled            bool      `json:"postgres_enabled"`
	MetricsEnabled             bool      `json:"metrics_enabled"`
	LogsEnabled                bool      `json:"logs_enabled"`
	TracesEnabled              bool      `json:"traces_enabled"`
	DashboardEnabled           bool      `json:"dashboard_enabled"`
	HostCPUCores               int       `json:"host_cpu_cores"`
	HostMemoryMB               int       `json:"host_memory_mb"`
	BackendTargets             []string  `json:"backend_targets"`
	VirtualHostRules           []string  `json:"virtual_host_rules"`
	Notes                      []string  `json:"notes"`
}

func Compile(cfg config.Config, mode string) EffectiveConfig {
	if mode == "" {
		mode = cfg.System.Mode
	}

	host := hostprofile.Detect()

	effective := EffectiveConfig{
		Name:                       cfg.System.Name,
		Deployment:                 cfg.System.Deployment,
		Mode:                       mode,
		GeneratedAt:                time.Now().UTC(),
		AutoMode:                   cfg.System.AutoMode,
		ControlPlaneLang:           cfg.Implementation.ControlPlaneLang,
		DataPlaneLang:              cfg.Implementation.DataPlaneLang,
		NodeAgentLang:              cfg.Implementation.NodeAgentLang,
		XDPManagerLang:             cfg.Implementation.XDPManagerLang,
		ConfigModel:                cfg.Implementation.ConfigModel,
		ProxyEngine:                cfg.Origin.Proxy.Engine,
		ListenPort:                 cfg.Origin.Proxy.ListenPort,
		CloudflareEnabled:          cfg.Edge.Cloudflare.Enabled,
		ProxyDNS:                   cfg.Edge.Cloudflare.ProxyDNS,
		HideOriginIP:               cfg.Edge.Cloudflare.HideOriginIP,
		LockOriginToCF:             cfg.Edge.Cloudflare.LockOriginToCF,
		CacheStatic:                cfg.Edge.Cloudflare.CacheStatic,
		TrustCFHeaders:             cfg.Edge.Cloudflare.TrustCFHeaders,
		XDPEnabled:                 cfg.Origin.XDP.Enabled,
		XDPMode:                    cfg.Origin.XDP.Mode,
		XDPInterface:               cfg.Origin.XDP.Interface,
		XDPAttachMode:              cfg.Origin.XDP.AttachMode,
		XDPSyncFromController:      cfg.Origin.XDP.SyncFromController,
		AllowCFOnly:                cfg.Origin.XDP.AllowCFOnly,
		XDPAllowlistCIDRs:          append([]string(nil), cfg.Origin.XDP.AllowlistCIDRs...),
		DropInvalidPackets:         cfg.Origin.XDP.DropInvalidPackets,
		PerIPGuard:                 cfg.Origin.XDP.PerIPGuard,
		RealIPFromEdgeOnly:         cfg.Origin.Proxy.RealIPFromEdgeOnly,
		CacheEnabled:               cfg.Origin.Proxy.CacheEnabled,
		Keepalive:                  cfg.Origin.Proxy.Keepalive,
		HTTPParser:                 cfg.Origin.Proxy.HTTPParser,
		WorkerModel:                cfg.Origin.Proxy.WorkerModel,
		WorkerThreads:              detectWorkerThreads(host),
		MaxActiveConnections:       cfg.Origin.Proxy.MaxActiveConnections,
		MaxKeepaliveRequests:       cfg.Origin.Proxy.MaxKeepaliveRequests,
		HeaderReadTimeoutMS:        cfg.Origin.Proxy.HeaderReadTimeoutMS,
		MaxRequestBytes:            cfg.Origin.Proxy.MaxRequestBytes,
		MaxResponseCacheEntries:    cfg.Origin.Proxy.MaxResponseCacheEntries,
		UpstreamConnectTimeoutMS:   cfg.Origin.Proxy.UpstreamConnectTimeoutMS,
		UpstreamReadTimeoutMS:      cfg.Origin.Proxy.UpstreamReadTimeoutMS,
		WAFEnabled:                 cfg.WAF.Enabled,
		WAFEngine:                  cfg.WAF.Engine,
		WAFMode:                    cfg.WAF.Mode,
		WAFParanoiaLevel:           cfg.WAF.ParanoiaLevel,
		WAFRuleset:                 cfg.WAF.Ruleset,
		CRSImportEnabled:           cfg.WAF.Compatibility.CRSImport,
		RateLimitEnabled:           cfg.RateLimit.Enabled,
		RateLimitBackend:           cfg.RateLimit.Backend,
		RateLimitRPS:               cfg.RateLimit.RequestsPerSecond,
		RateLimitBurst:             cfg.RateLimit.Burst,
		RateLimitMaxTrackedIPs:     cfg.RateLimit.MaxTrackedIPs,
		SensitivePaths:             append([]string(nil), cfg.RateLimit.SensitivePaths...),
		BotDefenseEnabled:          cfg.BotDefense.Enabled,
		DefaultAction:              cfg.BotDefense.DefaultAction,
		JSChallenge:                cfg.BotDefense.JSChallenge,
		ReplayProtection:           cfg.BotDefense.ReplayProtection,
		ChallengeDifficulty:        cfg.BotDefense.ChallengeDifficulty,
		ChallengeTokenCacheEntries: cfg.BotDefense.ChallengeTokenCacheEntries,
		ChallengePassTTLSeconds:    cfg.BotDefense.ChallengePassTTLSeconds,
		POWEnabled:                 cfg.BotDefense.POW.Enabled,
		POWProvider:                cfg.BotDefense.POW.Provider,
		ChallengeScope:             challengeScopeFromConfig(cfg),
		BehaviorEnabled:            cfg.Behavior.Enabled,
		BehaviorEngine:             cfg.Behavior.Engine,
		DecisionCacheTTL:           cfg.Behavior.DecisionCacheTTL,
		MaxDecisionEntries:         cfg.Behavior.MaxDecisionEntries,
		ReputationEnabled:          cfg.Behavior.ReputationEnabled,
		LearnBaseline:              cfg.Behavior.LearnBaseline,
		FingerprintTLS:             cfg.Behavior.Fingerprinting.TLS,
		FingerprintHTTP:            cfg.Behavior.Fingerprinting.HTTP,
		FingerprintCookie:          cfg.Behavior.Fingerprinting.Cookie,
		FingerprintSession:         cfg.Behavior.Fingerprinting.Session,
		ResponseAction:             cfg.BotDefense.DefaultAction,
		ZeroTouchBootstrap:         cfg.Implementation.ZeroTouchBootstrap,
		AutoTuneFromHost:           cfg.Automation.AutoTuneFromHost,
		CooldownMinutes:            cfg.Automation.CooldownMinutes,
		ClusterSyncEnabled:         cfg.Cluster.SyncEnabled,
		SyncBackend:                cfg.Cluster.SyncBackend,
		ConfigPushEnabled:          cfg.Cluster.ConfigPush,
		ConfigVersioning:           cfg.Cluster.ConfigVersioning,
		StagedRollout:              cfg.Cluster.StagedRollout,
		SharedDecisions:            cfg.Cluster.SharedDecisions,
		SharedDecisionTTLSeconds:   cfg.Cluster.SharedDecisionTTLSeconds,
		LocalDecisionPath:          cfg.Cluster.LocalDecisionPath,
		LocalObservationPath:       cfg.Cluster.LocalObservationPath,
		SharedRateLimitPath:        cfg.Cluster.SharedRateLimitPath,
		DecisionPollIntervalMS:     cfg.Cluster.DecisionPollIntervalMS,
		ObservationFlushInterval:   cfg.Cluster.ObservationFlushIntervalMS,
		ObservationWindowSeconds:   cfg.Cluster.ObservationWindowSeconds,
		SharedRateLimitThreshold:   cfg.Cluster.SharedRateLimitThreshold,
		SharedChallengeThreshold:   cfg.Cluster.SharedChallengeThreshold,
		NodeHeartbeatInterval:      cfg.Cluster.NodeHeartbeatIntervalSeconds,
		RedisEnabled:               cfg.Storage.RedisEnabled,
		RedisAddress:               cfg.Storage.RedisAddress,
		RedisPassword:              cfg.Storage.RedisPassword,
		RedisDB:                    cfg.Storage.RedisDB,
		RedisPrefix:                cfg.Storage.RedisPrefix,
		PostgresEnabled:            cfg.Storage.PostgresEnabled,
		MetricsEnabled:             cfg.Observability.Metrics,
		LogsEnabled:                cfg.Observability.Logs,
		TracesEnabled:              cfg.Observability.Traces,
		DashboardEnabled:           cfg.Observability.Dashboard,
		HostCPUCores:               host.CPUCores,
		HostMemoryMB:               host.MemoryMB,
		BackendTargets:             compileBackendTargets(cfg.Routing.BackendPools),
		VirtualHostRules:           compileVirtualHostRules(cfg.Routing.VirtualHosts),
	}

	applyHostTuning(&effective, cfg, host)

	switch mode {
	case config.ModeElevated:
		applyModeAction(&effective, cfg.Automation.Actions.Elevated)
		effective.ResponseAction = "soft_challenge"
		effective.Notes = append(effective.Notes, "elevated mode compiled from automation profile")
	case config.ModeUnderAttack:
		applyModeAction(&effective, cfg.Automation.Actions.UnderAttack)
		effective.ResponseAction = "pow_challenge"
		effective.SitewideChallenge = cfg.Automation.Actions.UnderAttack.EnableSitewideChallenge
		if effective.SitewideChallenge {
			effective.ChallengeScope = "sitewide"
		}
		effective.Notes = append(effective.Notes, "under_attack mode compiled from automation profile")
	case config.ModeMaintenance:
		effective.WAFMode = "detect_only"
		effective.ResponseAction = "observe"
		effective.Notes = append(effective.Notes, "maintenance mode prioritizes observability")
	default:
		effective.Notes = append(effective.Notes, "normal mode with always-on baseline defense")
	}

	if cfg.Edge.Cloudflare.Enabled {
		effective.Notes = append(effective.Notes, "cloudflare edge enabled for origin shielding")
	}
	if cfg.Automation.AutoTuneFromHost {
		effective.Notes = append(effective.Notes, "host-aware auto-tuning enabled")
	}

	return effective
}

func applyHostTuning(effective *EffectiveConfig, cfg config.Config, host hostprofile.Profile) {
	if !cfg.Automation.AutoTuneFromHost {
		return
	}

	switch {
	case host.CPUCores > 0 && host.CPUCores <= 2:
		effective.RateLimitRPS = maxInt(1, int(float64(effective.RateLimitRPS)*0.5))
		effective.RateLimitBurst = maxInt(5, int(float64(effective.RateLimitBurst)*0.5))
		effective.Notes = append(effective.Notes, "host autotune reduced rate limits for low CPU core count")
	case host.CPUCores >= 8 && host.MemoryMB >= 8192 && cfg.System.Deployment == "multi":
		effective.RateLimitRPS = int(float64(effective.RateLimitRPS) * 1.3)
		effective.RateLimitBurst = int(float64(effective.RateLimitBurst) * 1.3)
		effective.Notes = append(effective.Notes, "host autotune increased rate limits for multi-node high-capacity host")
	}

	if host.MemoryMB > 0 && host.MemoryMB < 4096 {
		effective.CacheEnabled = false
		effective.CacheAggressive = false
		effective.MaxActiveConnections = minInt(effective.MaxActiveConnections, 512)
		effective.Notes = append(effective.Notes, "host autotune disabled heavy cache behavior on low-memory host")
		effective.Notes = append(effective.Notes, "host autotune lowered max active connections on low-memory host")
	}
	if host.CPUCores >= 8 && host.MemoryMB >= 8192 {
		effective.MaxActiveConnections = maxInt(effective.MaxActiveConnections, 4096)
		effective.Notes = append(effective.Notes, "host autotune raised max active connections on high-capacity host")
	}
}

func applyModeAction(effective *EffectiveConfig, action config.ModeAction) {
	if action.XDPMode != "" {
		effective.XDPMode = action.XDPMode
	}
	if action.WAFParanoiaLevel > effective.WAFParanoiaLevel {
		effective.WAFParanoiaLevel = action.WAFParanoiaLevel
	}
	if action.RateLimitMultiplier > 0 {
		effective.RateLimitRPS = maxInt(1, int(float64(effective.RateLimitRPS)*action.RateLimitMultiplier))
		effective.RateLimitBurst = maxInt(1, int(float64(effective.RateLimitBurst)*action.RateLimitMultiplier))
	}
	if action.EnableSensitiveChallenge {
		effective.ChallengeScope = "sensitive_only"
	}
	if action.EnableSitewideChallenge {
		effective.SitewideChallenge = true
		effective.ChallengeScope = "sitewide"
	}
	if action.CacheAggressive {
		effective.CacheAggressive = true
	}
}

func DecideNextMode(cfg config.Config, currentMode string, metrics ObservedMetrics) (string, []string) {
	if !cfg.System.AutoMode || !cfg.Automation.Enabled {
		return currentMode, []string{"auto mode disabled; keeping current mode"}
	}

	var severity int
	var reasons []string

	if metrics.DirectOriginHits > 0 {
		severity += 2
		reasons = append(reasons, "direct origin hits detected")
	}
	if metrics.RPSMultiplier >= cfg.Automation.EscalateOn.HighRPSMultiplier {
		severity++
		reasons = append(reasons, "request rate exceeded high_rps_multiplier threshold")
	}
	if metrics.Error4xxRatio >= cfg.Automation.EscalateOn.High4xxRatio {
		severity++
		reasons = append(reasons, "4xx ratio exceeded threshold")
	}
	if metrics.WAFHitsPerMin >= cfg.Automation.EscalateOn.HighWAFHitsPerMinute {
		severity++
		reasons = append(reasons, "waf hits per minute exceeded threshold")
	}
	if metrics.ChallengeFailRatio >= cfg.Automation.EscalateOn.HighChallengeFailRatio {
		severity++
		reasons = append(reasons, "challenge fail ratio exceeded threshold")
	}
	if metrics.CPUPercent >= 85 {
		severity++
		reasons = append(reasons, "cpu pressure is high")
	}
	if metrics.ConnectionBacklog >= 1000 {
		severity++
		reasons = append(reasons, "connection backlog is high")
	}
	if metrics.FingerprintBursts > 0 {
		severity++
		reasons = append(reasons, "hot browser or transport fingerprint pressure detected")
	}
	if metrics.FingerprintFanout >= 4 {
		severity++
		reasons = append(reasons, "single fingerprint fan-out across multiple client ips detected")
	}

	switch {
	case severity >= 3:
		return config.ModeUnderAttack, reasons
	case severity >= 1:
		return config.ModeElevated, reasons
	default:
		return config.ModeNormal, []string{"metrics returned to baseline"}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func detectWorkerThreads(host hostprofile.Profile) int {
	switch {
	case host.CPUCores <= 1:
		return 1
	case host.CPUCores <= 4:
		return host.CPUCores
	default:
		return host.CPUCores - 1
	}
}

func challengeScopeFromConfig(cfg config.Config) string {
	if !cfg.BotDefense.Enabled || !cfg.BotDefense.POW.Enabled {
		return "off"
	}
	switch cfg.BotDefense.POW.Mode {
	case "off":
		return "off"
	case "full":
		return "sitewide"
	case "sensitive_only", "adaptive":
		return "sensitive_only"
	default:
		return "sensitive_only"
	}
}

func compileBackendTargets(pools []config.BackendPoolConfig) []string {
	var out []string
	for _, pool := range pools {
		for _, server := range pool.Servers {
			out = append(out,
				"pool="+pool.Name+
					"|balance="+pool.Balance+
					"|health_path="+pool.HealthCheckPath+
					"|health_interval_ms="+itoa(pool.HealthCheckIntervalMS)+
					"|health_timeout_ms="+itoa(pool.HealthCheckTimeoutMS)+
					"|unhealthy_threshold="+itoa(pool.UnhealthyThreshold)+
					"|healthy_threshold="+itoa(pool.HealthyThreshold)+
					"|fail_timeout_ms="+itoa(pool.FailTimeoutMS)+
					"|retry_attempts="+itoa(pool.RetryAttempts)+
					"|id="+server.ID+
					"|address="+server.Address+
					"|weight="+itoa(server.Weight))
		}
	}
	return out
}

func compileVirtualHostRules(hosts []config.VirtualHostConfig) []string {
	var out []string
	for _, host := range hosts {
		entry := "domains=" + join(host.Domains, ",") + "|default_pool=" + host.DefaultPool
		var rules []string
		for _, rule := range host.PathRules {
			rules = append(rules, rule.PathPrefix+":"+rule.Pool)
		}
		entry += "|paths=" + join(rules, ",")
		out = append(out, entry)
	}
	return out
}

func join(values []string, sep string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for i := 1; i < len(values); i++ {
		out += sep + values[i]
	}
	return out
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
