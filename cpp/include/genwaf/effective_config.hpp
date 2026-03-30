#pragma once

#include <string>
#include <vector>

namespace genwaf {

struct EffectiveConfig {
  std::string name = "gen-waf";
  std::string deployment = "single";
  std::string mode = "normal";
  std::string default_action = "allow";
  std::string proxy_engine = "gendp";
  std::string xdp_mode = "adaptive";
  std::string waf_engine = "genwaf-runtime";
  std::string waf_mode = "anomaly_block";
  std::string pow_provider = "altcha";
  std::string challenge_scope = "off";
  std::string response_action = "allow";
  std::string decision_cache_ttl = "60s";
  std::string sync_backend = "raft_or_redis";
  std::string http_parser = "native_cpp";
  std::string worker_model = "epoll_dispatch";
  std::string rate_limit_backend = "local";
  bool xdp_enabled = false;
  bool xdp_sync_from_controller = false;
  bool auto_mode = false;
  bool cloudflare_enabled = false;
  bool proxy_dns = false;
  bool hide_origin_ip = false;
  bool lock_origin_to_cf = false;
  bool cache_static = false;
  bool trust_cf_headers = false;
  bool allow_cf_only = false;
  bool drop_invalid_packets = false;
  bool per_ip_guard = false;
  std::vector<std::string> xdp_allowlist_cidrs;
  std::string xdp_interface;
  std::string xdp_attach_mode = "generic";
  bool real_ip_from_edge_only = false;
  bool cache_enabled = false;
  bool keepalive = false;
  bool waf_enabled = false;
  bool crs_import_enabled = false;
  bool rate_limit_enabled = false;
  bool bot_defense_enabled = false;
  bool js_challenge = false;
  bool replay_protection = true;
  bool pow_enabled = false;
  bool behavior_enabled = false;
  bool reputation_enabled = false;
  bool learn_baseline = false;
  bool fingerprint_tls = false;
  bool fingerprint_http = false;
  bool fingerprint_cookie = false;
  bool fingerprint_session = false;
  bool sitewide_challenge = false;
  bool cache_aggressive = false;
  bool cluster_sync_enabled = false;
  bool config_push_enabled = false;
  bool config_versioning = false;
  bool staged_rollout = false;
  bool shared_decisions = false;
  bool redis_enabled = false;
  std::string redis_address = "127.0.0.1:6379";
  std::string redis_password;
  int redis_db = 0;
  std::string redis_prefix = "genwaf";
  bool postgres_enabled = false;
  bool metrics_enabled = false;
  bool logs_enabled = false;
  bool traces_enabled = false;
  bool dashboard_enabled = false;
  bool zero_touch_bootstrap = false;
  int waf_paranoia_level = 0;
  int rate_limit_rps = 0;
  int rate_limit_burst = 0;
  int worker_threads = 1;
  int max_active_connections = 2048;
  int max_keepalive_requests = 32;
  int cooldown_minutes = 0;
  int host_cpu_cores = 0;
  int host_memory_mb = 0;
  int listen_port = 80;
  int header_read_timeout_ms = 2000;
  int max_request_bytes = 1048576;
  int max_response_cache_entries = 1024;
  int upstream_connect_timeout_ms = 1500;
  int upstream_read_timeout_ms = 5000;
  int rate_limit_max_tracked_ips = 50000;
  int challenge_difficulty = 4;
  int challenge_token_cache_entries = 20000;
  int challenge_pass_ttl_seconds = 300;
  int max_decision_entries = 20000;
  int shared_decision_ttl_seconds = 600;
  int decision_poll_interval_ms = 1000;
  int observation_flush_interval_ms = 2000;
  int observation_window_seconds = 15;
  int shared_rate_limit_threshold = 250;
  int shared_challenge_threshold = 120;
  int node_heartbeat_interval_seconds = 15;
  std::string local_decision_path = "runtime/cluster-decisions.json";
  std::string local_observation_path = "runtime/node-observations.json";
  std::string shared_rate_limit_path = "runtime/cluster-rate-limits.json";
  std::vector<std::string> sensitive_paths;
  std::vector<std::string> backend_targets;
  std::vector<std::string> virtual_host_rules;
};

EffectiveConfig load_effective_config(const std::string& path);
std::string summarize(const EffectiveConfig& config);

}  // namespace genwaf
