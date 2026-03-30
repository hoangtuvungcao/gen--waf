package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ModeNormal      = "normal"
	ModeElevated    = "elevated"
	ModeUnderAttack = "under_attack"
	ModeMaintenance = "maintenance"
)

type Config struct {
	System         SystemConfig         `yaml:"system" json:"system"`
	Implementation ImplementationConfig `yaml:"implementation" json:"implementation"`
	Edge           EdgeConfig           `yaml:"edge" json:"edge"`
	Origin         OriginConfig         `yaml:"origin" json:"origin"`
	Routing        RoutingConfig        `yaml:"routing" json:"routing"`
	WAF            WAFConfig            `yaml:"waf" json:"waf"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit" json:"rate_limit"`
	BotDefense     BotDefenseConfig     `yaml:"bot_defense" json:"bot_defense"`
	Behavior       BehaviorConfig       `yaml:"behavior" json:"behavior"`
	Automation     AutomationConfig     `yaml:"automation" json:"automation"`
	Cluster        ClusterConfig        `yaml:"cluster" json:"cluster"`
	Storage        StorageConfig        `yaml:"storage" json:"storage"`
	Observability  ObservabilityConfig  `yaml:"observability" json:"observability"`
}

type SystemConfig struct {
	Name       string `yaml:"name" json:"name"`
	Deployment string `yaml:"deployment" json:"deployment"`
	Mode       string `yaml:"mode" json:"mode"`
	AutoMode   bool   `yaml:"auto_mode" json:"auto_mode"`
}

type ImplementationConfig struct {
	ControlPlaneLang   string `yaml:"control_plane_lang" json:"control_plane_lang"`
	DataPlaneLang      string `yaml:"data_plane_lang" json:"data_plane_lang"`
	NodeAgentLang      string `yaml:"node_agent_lang" json:"node_agent_lang"`
	XDPManagerLang     string `yaml:"xdp_manager_lang" json:"xdp_manager_lang"`
	ConfigModel        string `yaml:"config_model" json:"config_model"`
	ZeroTouchBootstrap bool   `yaml:"zero_touch_bootstrap" json:"zero_touch_bootstrap"`
}

type EdgeConfig struct {
	Cloudflare CloudflareConfig `yaml:"cloudflare" json:"cloudflare"`
}

type CloudflareConfig struct {
	Enabled        bool `yaml:"enabled" json:"enabled"`
	ProxyDNS       bool `yaml:"proxy_dns" json:"proxy_dns"`
	HideOriginIP   bool `yaml:"hide_origin_ip" json:"hide_origin_ip"`
	LockOriginToCF bool `yaml:"lock_origin_to_cf" json:"lock_origin_to_cf"`
	CacheStatic    bool `yaml:"cache_static" json:"cache_static"`
	TrustCFHeaders bool `yaml:"trust_cf_headers" json:"trust_cf_headers"`
}

type OriginConfig struct {
	XDP   XDPConfig   `yaml:"xdp" json:"xdp"`
	Proxy ProxyConfig `yaml:"proxy" json:"proxy"`
}

type XDPConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	Mode               string   `yaml:"mode" json:"mode"`
	Interface          string   `yaml:"interface" json:"interface"`
	AttachMode         string   `yaml:"attach_mode" json:"attach_mode"`
	AllowCFOnly        bool     `yaml:"allow_cf_only" json:"allow_cf_only"`
	DropInvalidPackets bool     `yaml:"drop_invalid_packets" json:"drop_invalid_packets"`
	PerIPGuard         bool     `yaml:"per_ip_guard" json:"per_ip_guard"`
	SyncFromController bool     `yaml:"sync_from_controller" json:"sync_from_controller"`
	AllowlistCIDRs     []string `yaml:"allowlist_cidrs" json:"allowlist_cidrs"`
}

type ProxyConfig struct {
	Engine                   string `yaml:"engine" json:"engine"`
	ListenPort               int    `yaml:"listen_port" json:"listen_port"`
	RealIPFromEdgeOnly       bool   `yaml:"real_ip_from_edge_only" json:"real_ip_from_edge_only"`
	CacheEnabled             bool   `yaml:"cache_enabled" json:"cache_enabled"`
	Keepalive                bool   `yaml:"keepalive" json:"keepalive"`
	HTTPParser               string `yaml:"http_parser" json:"http_parser"`
	WorkerModel              string `yaml:"worker_model" json:"worker_model"`
	MaxActiveConnections     int    `yaml:"max_active_connections" json:"max_active_connections"`
	MaxKeepaliveRequests     int    `yaml:"max_keepalive_requests" json:"max_keepalive_requests"`
	HeaderReadTimeoutMS      int    `yaml:"header_read_timeout_ms" json:"header_read_timeout_ms"`
	MaxRequestBytes          int    `yaml:"max_request_bytes" json:"max_request_bytes"`
	MaxResponseCacheEntries  int    `yaml:"max_response_cache_entries" json:"max_response_cache_entries"`
	UpstreamConnectTimeoutMS int    `yaml:"upstream_connect_timeout_ms" json:"upstream_connect_timeout_ms"`
	UpstreamReadTimeoutMS    int    `yaml:"upstream_read_timeout_ms" json:"upstream_read_timeout_ms"`
}

type RoutingConfig struct {
	BackendPools []BackendPoolConfig `yaml:"backend_pools" json:"backend_pools"`
	VirtualHosts []VirtualHostConfig `yaml:"virtual_hosts" json:"virtual_hosts"`
}

type BackendPoolConfig struct {
	Name                  string                `yaml:"name" json:"name"`
	Balance               string                `yaml:"balance" json:"balance"`
	HealthCheckPath       string                `yaml:"health_check_path" json:"health_check_path"`
	HealthCheckIntervalMS int                   `yaml:"health_check_interval_ms" json:"health_check_interval_ms"`
	HealthCheckTimeoutMS  int                   `yaml:"health_check_timeout_ms" json:"health_check_timeout_ms"`
	UnhealthyThreshold    int                   `yaml:"unhealthy_threshold" json:"unhealthy_threshold"`
	HealthyThreshold      int                   `yaml:"healthy_threshold" json:"healthy_threshold"`
	FailTimeoutMS         int                   `yaml:"fail_timeout_ms" json:"fail_timeout_ms"`
	RetryAttempts         int                   `yaml:"retry_attempts" json:"retry_attempts"`
	Servers               []BackendServerConfig `yaml:"servers" json:"servers"`
}

type BackendServerConfig struct {
	ID      string `yaml:"id" json:"id"`
	Address string `yaml:"address" json:"address"`
	Weight  int    `yaml:"weight" json:"weight"`
}

type VirtualHostConfig struct {
	Domains     []string         `yaml:"domains" json:"domains"`
	DefaultPool string           `yaml:"default_pool" json:"default_pool"`
	PathRules   []PathRuleConfig `yaml:"path_rules" json:"path_rules"`
}

type PathRuleConfig struct {
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
	Pool       string `yaml:"pool" json:"pool"`
}

type WAFConfig struct {
	Enabled       bool             `yaml:"enabled" json:"enabled"`
	Engine        string           `yaml:"engine" json:"engine"`
	Ruleset       string           `yaml:"ruleset" json:"ruleset"`
	ParanoiaLevel int              `yaml:"paranoia_level" json:"paranoia_level"`
	Mode          string           `yaml:"mode" json:"mode"`
	Compatibility WAFCompatibility `yaml:"compatibility" json:"compatibility"`
}

type WAFCompatibility struct {
	CRSImport bool `yaml:"crs_import" json:"crs_import"`
}

type RateLimitConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	Backend           string   `yaml:"backend" json:"backend"`
	RequestsPerSecond int      `yaml:"requests_per_second" json:"requests_per_second"`
	Burst             int      `yaml:"burst" json:"burst"`
	MaxTrackedIPs     int      `yaml:"max_tracked_ips" json:"max_tracked_ips"`
	SensitivePaths    []string `yaml:"sensitive_paths" json:"sensitive_paths"`
}

type BotDefenseConfig struct {
	Enabled                    bool      `yaml:"enabled" json:"enabled"`
	DefaultAction              string    `yaml:"default_action" json:"default_action"`
	JSChallenge                bool      `yaml:"js_challenge" json:"js_challenge"`
	ReplayProtection           bool      `yaml:"replay_protection" json:"replay_protection"`
	ChallengeDifficulty        int       `yaml:"challenge_difficulty" json:"challenge_difficulty"`
	ChallengeTokenCacheEntries int       `yaml:"challenge_token_cache_entries" json:"challenge_token_cache_entries"`
	ChallengePassTTLSeconds    int       `yaml:"challenge_pass_ttl_seconds" json:"challenge_pass_ttl_seconds"`
	POW                        POWConfig `yaml:"pow" json:"pow"`
}

type POWConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Provider string `yaml:"provider" json:"provider"`
	Mode     string `yaml:"mode" json:"mode"`
}

type BehaviorConfig struct {
	Enabled            bool                 `yaml:"enabled" json:"enabled"`
	Engine             string               `yaml:"engine" json:"engine"`
	DecisionCacheTTL   string               `yaml:"decision_cache_ttl" json:"decision_cache_ttl"`
	MaxDecisionEntries int                  `yaml:"max_decision_entries" json:"max_decision_entries"`
	ReputationEnabled  bool                 `yaml:"reputation_enabled" json:"reputation_enabled"`
	LearnBaseline      bool                 `yaml:"learn_baseline" json:"learn_baseline"`
	Fingerprinting     FingerprintingConfig `yaml:"fingerprinting" json:"fingerprinting"`
}

type FingerprintingConfig struct {
	TLS     bool `yaml:"tls" json:"tls"`
	HTTP    bool `yaml:"http" json:"http"`
	Cookie  bool `yaml:"cookie" json:"cookie"`
	Session bool `yaml:"session" json:"session"`
}

type AutomationConfig struct {
	Enabled          bool               `yaml:"enabled" json:"enabled"`
	BaselineLearning bool               `yaml:"baseline_learning" json:"baseline_learning"`
	AutoTuneFromHost bool               `yaml:"auto_tune_from_host" json:"auto_tune_from_host"`
	ZeroTouchRollout bool               `yaml:"zero_touch_rollout" json:"zero_touch_rollout"`
	EscalateOn       EscalationTriggers `yaml:"escalate_on" json:"escalate_on"`
	CooldownMinutes  int                `yaml:"cooldown_minutes" json:"cooldown_minutes"`
	Actions          AutomationActions  `yaml:"actions" json:"actions"`
}

type EscalationTriggers struct {
	HighRPSMultiplier      float64 `yaml:"high_rps_multiplier" json:"high_rps_multiplier"`
	High4xxRatio           float64 `yaml:"high_4xx_ratio" json:"high_4xx_ratio"`
	HighWAFHitsPerMinute   int     `yaml:"high_waf_hits_per_min" json:"high_waf_hits_per_min"`
	HighChallengeFailRatio float64 `yaml:"high_challenge_fail_ratio" json:"high_challenge_fail_ratio"`
}

type AutomationActions struct {
	Elevated    ModeAction `yaml:"elevated" json:"elevated"`
	UnderAttack ModeAction `yaml:"under_attack" json:"under_attack"`
}

type ModeAction struct {
	XDPMode                  string  `yaml:"xdp_mode" json:"xdp_mode"`
	RateLimitMultiplier      float64 `yaml:"rate_limit_multiplier" json:"rate_limit_multiplier"`
	EnableSensitiveChallenge bool    `yaml:"enable_sensitive_challenge" json:"enable_sensitive_challenge"`
	EnableSitewideChallenge  bool    `yaml:"enable_sitewide_challenge" json:"enable_sitewide_challenge"`
	WAFParanoiaLevel         int     `yaml:"waf_paranoia_level" json:"waf_paranoia_level"`
	CacheAggressive          bool    `yaml:"cache_aggressive" json:"cache_aggressive"`
}

type ClusterConfig struct {
	SyncEnabled                  bool   `yaml:"sync_enabled" json:"sync_enabled"`
	SyncBackend                  string `yaml:"sync_backend" json:"sync_backend"`
	ConfigPush                   bool   `yaml:"config_push" json:"config_push"`
	ConfigVersioning             bool   `yaml:"config_versioning" json:"config_versioning"`
	StagedRollout                bool   `yaml:"staged_rollout" json:"staged_rollout"`
	SharedDecisions              bool   `yaml:"shared_decisions" json:"shared_decisions"`
	SharedDecisionTTLSeconds     int    `yaml:"shared_decision_ttl_seconds" json:"shared_decision_ttl_seconds"`
	LocalDecisionPath            string `yaml:"local_decision_path" json:"local_decision_path"`
	LocalObservationPath         string `yaml:"local_observation_path" json:"local_observation_path"`
	SharedRateLimitPath          string `yaml:"shared_rate_limit_path" json:"shared_rate_limit_path"`
	DecisionPollIntervalMS       int    `yaml:"decision_poll_interval_ms" json:"decision_poll_interval_ms"`
	ObservationFlushIntervalMS   int    `yaml:"observation_flush_interval_ms" json:"observation_flush_interval_ms"`
	ObservationWindowSeconds     int    `yaml:"observation_window_seconds" json:"observation_window_seconds"`
	SharedRateLimitThreshold     int    `yaml:"shared_rate_limit_threshold" json:"shared_rate_limit_threshold"`
	SharedChallengeThreshold     int    `yaml:"shared_challenge_threshold" json:"shared_challenge_threshold"`
	NodeHeartbeatIntervalSeconds int    `yaml:"node_heartbeat_interval_seconds" json:"node_heartbeat_interval_seconds"`
	ControllerStatePath          string `yaml:"controller_state_path" json:"controller_state_path"`
}

type StorageConfig struct {
	RedisEnabled    bool   `yaml:"redis_enabled" json:"redis_enabled"`
	RedisAddress    string `yaml:"redis_address" json:"redis_address"`
	RedisPassword   string `yaml:"redis_password" json:"redis_password"`
	RedisDB         int    `yaml:"redis_db" json:"redis_db"`
	RedisPrefix     string `yaml:"redis_prefix" json:"redis_prefix"`
	PostgresEnabled bool   `yaml:"postgres_enabled" json:"postgres_enabled"`
}

type ObservabilityConfig struct {
	Metrics   bool `yaml:"metrics" json:"metrics"`
	Logs      bool `yaml:"logs" json:"logs"`
	Traces    bool `yaml:"traces" json:"traces"`
	Dashboard bool `yaml:"dashboard" json:"dashboard"`
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.System.Name == "" {
		c.System.Name = "gen-waf"
	}
	if c.System.Deployment == "" {
		c.System.Deployment = "single"
	}
	if c.System.Mode == "" {
		c.System.Mode = ModeNormal
	}
	if c.Implementation.ControlPlaneLang == "" {
		c.Implementation.ControlPlaneLang = "go"
	}
	if c.Implementation.DataPlaneLang == "" {
		c.Implementation.DataPlaneLang = "cpp"
	}
	if c.Implementation.NodeAgentLang == "" {
		c.Implementation.NodeAgentLang = "go"
	}
	if c.Implementation.XDPManagerLang == "" {
		c.Implementation.XDPManagerLang = "cpp"
	}
	if c.Implementation.ConfigModel == "" {
		c.Implementation.ConfigModel = "declarative"
	}
	if c.Origin.XDP.Mode == "" {
		c.Origin.XDP.Mode = "adaptive"
	}
	if c.Origin.XDP.AttachMode == "" {
		c.Origin.XDP.AttachMode = "generic"
	}
	if c.Origin.Proxy.Engine == "" {
		c.Origin.Proxy.Engine = "gendp"
	}
	if c.Origin.Proxy.HTTPParser == "" {
		c.Origin.Proxy.HTTPParser = "native_cpp"
	}
	if c.Origin.Proxy.ListenPort == 0 {
		c.Origin.Proxy.ListenPort = 80
	}
	if c.Origin.Proxy.WorkerModel == "" {
		c.Origin.Proxy.WorkerModel = "epoll_dispatch"
	}
	if c.Origin.Proxy.MaxActiveConnections == 0 {
		c.Origin.Proxy.MaxActiveConnections = 2048
	}
	if c.Origin.Proxy.MaxKeepaliveRequests == 0 {
		c.Origin.Proxy.MaxKeepaliveRequests = 32
	}
	if c.Origin.Proxy.HeaderReadTimeoutMS == 0 {
		c.Origin.Proxy.HeaderReadTimeoutMS = 2000
	}
	if c.Origin.Proxy.MaxRequestBytes == 0 {
		c.Origin.Proxy.MaxRequestBytes = 1048576
	}
	if c.Origin.Proxy.MaxResponseCacheEntries == 0 {
		c.Origin.Proxy.MaxResponseCacheEntries = 1024
	}
	if c.Origin.Proxy.UpstreamConnectTimeoutMS == 0 {
		c.Origin.Proxy.UpstreamConnectTimeoutMS = 1500
	}
	if c.Origin.Proxy.UpstreamReadTimeoutMS == 0 {
		c.Origin.Proxy.UpstreamReadTimeoutMS = 5000
	}
	if c.WAF.Engine == "" {
		c.WAF.Engine = "genwaf-runtime"
	}
	if c.WAF.Ruleset == "" {
		c.WAF.Ruleset = "gen_policy_v1"
	}
	if c.WAF.Mode == "" {
		c.WAF.Mode = "anomaly_block"
	}
	if c.WAF.ParanoiaLevel == 0 {
		c.WAF.ParanoiaLevel = 2
	}
	if c.RateLimit.Backend == "" {
		c.RateLimit.Backend = "local"
	}
	if c.RateLimit.RequestsPerSecond == 0 {
		c.RateLimit.RequestsPerSecond = 10
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 30
	}
	if c.RateLimit.MaxTrackedIPs == 0 {
		c.RateLimit.MaxTrackedIPs = 50000
	}
	if c.BotDefense.DefaultAction == "" {
		c.BotDefense.DefaultAction = "allow"
	}
	if c.BotDefense.ChallengeDifficulty == 0 {
		c.BotDefense.ChallengeDifficulty = 4
	}
	if c.BotDefense.ChallengeTokenCacheEntries == 0 {
		c.BotDefense.ChallengeTokenCacheEntries = 20000
	}
	if c.BotDefense.ChallengePassTTLSeconds == 0 {
		c.BotDefense.ChallengePassTTLSeconds = 300
	}
	if c.BotDefense.POW.Provider == "" {
		c.BotDefense.POW.Provider = "altcha"
	}
	if c.BotDefense.POW.Mode == "" {
		c.BotDefense.POW.Mode = "adaptive"
	}
	if c.Behavior.Engine == "" {
		c.Behavior.Engine = "genbrain"
	}
	if c.Behavior.DecisionCacheTTL == "" {
		c.Behavior.DecisionCacheTTL = "60s"
	}
	if c.Behavior.MaxDecisionEntries == 0 {
		c.Behavior.MaxDecisionEntries = 20000
	}
	if c.Automation.CooldownMinutes == 0 {
		c.Automation.CooldownMinutes = 20
	}
	if c.Automation.EscalateOn.HighRPSMultiplier == 0 {
		c.Automation.EscalateOn.HighRPSMultiplier = 3
	}
	if c.Automation.EscalateOn.High4xxRatio == 0 {
		c.Automation.EscalateOn.High4xxRatio = 0.4
	}
	if c.Automation.EscalateOn.HighWAFHitsPerMinute == 0 {
		c.Automation.EscalateOn.HighWAFHitsPerMinute = 200
	}
	if c.Automation.EscalateOn.HighChallengeFailRatio == 0 {
		c.Automation.EscalateOn.HighChallengeFailRatio = 0.6
	}
	if c.Automation.Actions.Elevated.XDPMode == "" {
		c.Automation.Actions.Elevated.XDPMode = "adaptive"
	}
	if c.Automation.Actions.Elevated.RateLimitMultiplier == 0 {
		c.Automation.Actions.Elevated.RateLimitMultiplier = 0.7
	}
	if c.Automation.Actions.Elevated.WAFParanoiaLevel == 0 {
		c.Automation.Actions.Elevated.WAFParanoiaLevel = 3
	}
	if c.Automation.Actions.UnderAttack.XDPMode == "" {
		c.Automation.Actions.UnderAttack.XDPMode = "strict"
	}
	if c.Automation.Actions.UnderAttack.RateLimitMultiplier == 0 {
		c.Automation.Actions.UnderAttack.RateLimitMultiplier = 0.4
	}
	if c.Automation.Actions.UnderAttack.WAFParanoiaLevel == 0 {
		c.Automation.Actions.UnderAttack.WAFParanoiaLevel = 4
	}
	if c.Cluster.SyncBackend == "" {
		c.Cluster.SyncBackend = "controller"
	}
	if c.Cluster.SharedDecisionTTLSeconds == 0 {
		c.Cluster.SharedDecisionTTLSeconds = 600
	}
	if c.Cluster.LocalDecisionPath == "" {
		c.Cluster.LocalDecisionPath = "runtime/cluster-decisions.json"
	}
	if c.Cluster.LocalObservationPath == "" {
		c.Cluster.LocalObservationPath = "runtime/node-observations.json"
	}
	if c.Cluster.SharedRateLimitPath == "" {
		c.Cluster.SharedRateLimitPath = "runtime/cluster-rate-limits.json"
	}
	if c.Cluster.DecisionPollIntervalMS == 0 {
		c.Cluster.DecisionPollIntervalMS = 1000
	}
	if c.Cluster.ObservationFlushIntervalMS == 0 {
		c.Cluster.ObservationFlushIntervalMS = 2000
	}
	if c.Cluster.ObservationWindowSeconds == 0 {
		c.Cluster.ObservationWindowSeconds = 15
	}
	if c.Cluster.SharedRateLimitThreshold == 0 {
		c.Cluster.SharedRateLimitThreshold = 250
	}
	if c.Cluster.SharedChallengeThreshold == 0 {
		c.Cluster.SharedChallengeThreshold = 120
	}
	if c.Cluster.NodeHeartbeatIntervalSeconds == 0 {
		c.Cluster.NodeHeartbeatIntervalSeconds = 15
	}
	if c.Cluster.ControllerStatePath == "" {
		c.Cluster.ControllerStatePath = "runtime/controller-state.json"
	}
	if c.Storage.RedisAddress == "" {
		c.Storage.RedisAddress = "127.0.0.1:6379"
	}
	if c.Storage.RedisPrefix == "" {
		c.Storage.RedisPrefix = "genwaf"
	}
	for i := range c.Routing.BackendPools {
		if c.Routing.BackendPools[i].Balance == "" {
			c.Routing.BackendPools[i].Balance = "round_robin"
		}
		if c.Routing.BackendPools[i].HealthCheckPath == "" {
			c.Routing.BackendPools[i].HealthCheckPath = "/healthz"
		}
		if c.Routing.BackendPools[i].HealthCheckIntervalMS == 0 {
			c.Routing.BackendPools[i].HealthCheckIntervalMS = 5000
		}
		if c.Routing.BackendPools[i].HealthCheckTimeoutMS == 0 {
			c.Routing.BackendPools[i].HealthCheckTimeoutMS = 1000
		}
		if c.Routing.BackendPools[i].UnhealthyThreshold == 0 {
			c.Routing.BackendPools[i].UnhealthyThreshold = 2
		}
		if c.Routing.BackendPools[i].HealthyThreshold == 0 {
			c.Routing.BackendPools[i].HealthyThreshold = 2
		}
		if c.Routing.BackendPools[i].FailTimeoutMS == 0 {
			c.Routing.BackendPools[i].FailTimeoutMS = 10000
		}
		if c.Routing.BackendPools[i].RetryAttempts == 0 {
			c.Routing.BackendPools[i].RetryAttempts = 1
		}
		for j := range c.Routing.BackendPools[i].Servers {
			if c.Routing.BackendPools[i].Servers[j].Weight == 0 {
				c.Routing.BackendPools[i].Servers[j].Weight = 1
			}
		}
	}

	// Validate decision cache TTL early so operator feedback is immediate.
	if _, err := time.ParseDuration(c.Behavior.DecisionCacheTTL); err != nil {
		c.Behavior.DecisionCacheTTL = "60s"
	}
}

func (c Config) Validate() error {
	if c.System.Name == "" {
		return fmt.Errorf("system.name must not be empty")
	}
	switch c.System.Deployment {
	case "single", "multi":
	default:
		return fmt.Errorf("system.deployment must be single or multi")
	}
	switch c.System.Mode {
	case ModeNormal, ModeElevated, ModeUnderAttack, ModeMaintenance:
	default:
		return fmt.Errorf("system.mode must be one of normal, elevated, under_attack, maintenance")
	}
	if _, err := time.ParseDuration(c.Behavior.DecisionCacheTTL); err != nil {
		return fmt.Errorf("behavior.decision_cache_ttl invalid: %w", err)
	}
	if c.RateLimit.RequestsPerSecond < 0 || c.RateLimit.Burst < 0 {
		return fmt.Errorf("rate limit values must be non-negative")
	}
	switch c.RateLimit.Backend {
	case "local", "cluster_shared", "redis_native":
	default:
		return fmt.Errorf("rate_limit.backend currently supports local, cluster_shared, or redis_native")
	}
	if c.WAF.ParanoiaLevel < 0 {
		return fmt.Errorf("waf.paranoia_level must be non-negative")
	}
	switch c.WAF.Mode {
	case "anomaly_block", "detect_only", "block_strict":
	default:
		return fmt.Errorf("waf.mode must be anomaly_block, detect_only, or block_strict")
	}
	if c.Origin.Proxy.ListenPort <= 0 {
		return fmt.Errorf("origin.proxy.listen_port must be positive")
	}
	if c.Origin.Proxy.HeaderReadTimeoutMS <= 0 {
		return fmt.Errorf("origin.proxy.header_read_timeout_ms must be positive")
	}
	if c.Origin.Proxy.MaxActiveConnections <= 0 {
		return fmt.Errorf("origin.proxy.max_active_connections must be positive")
	}
	if c.Origin.Proxy.MaxKeepaliveRequests <= 0 {
		return fmt.Errorf("origin.proxy.max_keepalive_requests must be positive")
	}
	if c.Origin.Proxy.MaxRequestBytes <= 0 {
		return fmt.Errorf("origin.proxy.max_request_bytes must be positive")
	}
	if c.Origin.Proxy.MaxResponseCacheEntries <= 0 {
		return fmt.Errorf("origin.proxy.max_response_cache_entries must be positive")
	}
	switch c.Origin.XDP.Mode {
	case "off", "monitor", "adaptive", "strict":
	default:
		return fmt.Errorf("origin.xdp.mode must be off, monitor, adaptive, or strict")
	}
	switch c.Origin.XDP.AttachMode {
	case "generic", "native":
	default:
		return fmt.Errorf("origin.xdp.attach_mode must be generic or native")
	}
	switch c.BotDefense.DefaultAction {
	case "allow", "soft_challenge", "pow_challenge":
	default:
		return fmt.Errorf("bot_defense.default_action must be allow, soft_challenge, or pow_challenge")
	}
	switch c.BotDefense.POW.Provider {
	case "altcha", "anubis", "mcaptcha":
	default:
		return fmt.Errorf("bot_defense.pow.provider must be altcha, anubis, or mcaptcha")
	}
	switch c.BotDefense.POW.Mode {
	case "off", "sensitive_only", "adaptive", "full":
	default:
		return fmt.Errorf("bot_defense.pow.mode must be off, sensitive_only, adaptive, or full")
	}
	if c.BotDefense.ChallengeDifficulty < 0 || c.BotDefense.ChallengeDifficulty > 8 {
		return fmt.Errorf("bot_defense.challenge_difficulty must be between 0 and 8")
	}
	if c.BotDefense.ChallengeTokenCacheEntries <= 0 {
		return fmt.Errorf("bot_defense.challenge_token_cache_entries must be positive")
	}
	if c.BotDefense.ChallengePassTTLSeconds <= 0 {
		return fmt.Errorf("bot_defense.challenge_pass_ttl_seconds must be positive")
	}
	if c.RateLimit.MaxTrackedIPs <= 0 {
		return fmt.Errorf("rate_limit.max_tracked_ips must be positive")
	}
	if c.Behavior.MaxDecisionEntries <= 0 {
		return fmt.Errorf("behavior.max_decision_entries must be positive")
	}
	pools := make(map[string]struct{}, len(c.Routing.BackendPools))
	for _, pool := range c.Routing.BackendPools {
		if pool.Name == "" {
			return fmt.Errorf("routing.backend_pools.name must not be empty")
		}
		switch pool.Balance {
		case "round_robin", "ip_hash":
		default:
			return fmt.Errorf("routing.backend_pools.%s balance must be round_robin or ip_hash", pool.Name)
		}
		pools[pool.Name] = struct{}{}
		if len(pool.Servers) == 0 {
			return fmt.Errorf("routing.backend_pools.%s must have at least one server", pool.Name)
		}
		if pool.HealthCheckIntervalMS <= 0 {
			return fmt.Errorf("routing.backend_pools.%s health_check_interval_ms must be positive", pool.Name)
		}
		if pool.HealthCheckTimeoutMS <= 0 {
			return fmt.Errorf("routing.backend_pools.%s health_check_timeout_ms must be positive", pool.Name)
		}
		if pool.UnhealthyThreshold <= 0 {
			return fmt.Errorf("routing.backend_pools.%s unhealthy_threshold must be positive", pool.Name)
		}
		if pool.HealthyThreshold <= 0 {
			return fmt.Errorf("routing.backend_pools.%s healthy_threshold must be positive", pool.Name)
		}
		if pool.FailTimeoutMS <= 0 {
			return fmt.Errorf("routing.backend_pools.%s fail_timeout_ms must be positive", pool.Name)
		}
		if pool.RetryAttempts < 0 {
			return fmt.Errorf("routing.backend_pools.%s retry_attempts must be non-negative", pool.Name)
		}
		for _, server := range pool.Servers {
			if server.Address == "" {
				return fmt.Errorf("routing.backend_pools.%s server address must not be empty", pool.Name)
			}
		}
	}
	for _, host := range c.Routing.VirtualHosts {
		if len(host.Domains) == 0 {
			return fmt.Errorf("routing.virtual_hosts must include at least one domain")
		}
		if host.DefaultPool == "" {
			return fmt.Errorf("routing.virtual_hosts default_pool must not be empty")
		}
		if _, ok := pools[host.DefaultPool]; !ok {
			return fmt.Errorf("routing.virtual_hosts default_pool %q not found", host.DefaultPool)
		}
		for _, rule := range host.PathRules {
			if rule.PathPrefix == "" {
				return fmt.Errorf("routing.virtual_hosts path_rules.path_prefix must not be empty")
			}
			if _, ok := pools[rule.Pool]; !ok {
				return fmt.Errorf("routing.virtual_hosts path_rules.pool %q not found", rule.Pool)
			}
		}
	}
	if c.Cluster.SyncBackend != "controller" {
		return fmt.Errorf("cluster.sync_backend currently supports only controller")
	}
	if c.Cluster.SharedDecisionTTLSeconds <= 0 {
		return fmt.Errorf("cluster.shared_decision_ttl_seconds must be positive")
	}
	if c.Cluster.DecisionPollIntervalMS <= 0 {
		return fmt.Errorf("cluster.decision_poll_interval_ms must be positive")
	}
	if c.Cluster.NodeHeartbeatIntervalSeconds <= 0 {
		return fmt.Errorf("cluster.node_heartbeat_interval_seconds must be positive")
	}
	if c.Cluster.LocalDecisionPath == "" {
		return fmt.Errorf("cluster.local_decision_path must not be empty")
	}
	if c.Cluster.LocalObservationPath == "" {
		return fmt.Errorf("cluster.local_observation_path must not be empty")
	}
	if c.Cluster.SharedRateLimitPath == "" {
		return fmt.Errorf("cluster.shared_rate_limit_path must not be empty")
	}
	if c.Cluster.ControllerStatePath == "" {
		return fmt.Errorf("cluster.controller_state_path must not be empty")
	}
	if c.Cluster.ObservationFlushIntervalMS <= 0 {
		return fmt.Errorf("cluster.observation_flush_interval_ms must be positive")
	}
	if c.Cluster.ObservationWindowSeconds <= 0 {
		return fmt.Errorf("cluster.observation_window_seconds must be positive")
	}
	if c.Cluster.SharedRateLimitThreshold <= 0 {
		return fmt.Errorf("cluster.shared_rate_limit_threshold must be positive")
	}
	if c.Cluster.SharedChallengeThreshold <= 0 {
		return fmt.Errorf("cluster.shared_challenge_threshold must be positive")
	}
	if c.Storage.RedisEnabled && c.Storage.RedisAddress == "" {
		return fmt.Errorf("storage.redis_address must not be empty when redis is enabled")
	}
	if c.Storage.PostgresEnabled {
		return fmt.Errorf("storage.postgres_enabled is not implemented yet; keep it false")
	}
	if c.Observability.Traces {
		return fmt.Errorf("observability.traces is not implemented yet; keep it false")
	}
	for _, cidr := range c.Origin.XDP.AllowlistCIDRs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("origin.xdp.allowlist_cidrs contains invalid CIDR %q: %w", cidr, err)
		}
		if ip == nil || ip.To4() == nil || network.IP.To4() == nil {
			return fmt.Errorf("origin.xdp.allowlist_cidrs currently supports IPv4 only: %q", cidr)
		}
	}
	if c.Automation.CooldownMinutes < 0 {
		return fmt.Errorf("automation.cooldown_minutes must be non-negative")
	}
	return nil
}
