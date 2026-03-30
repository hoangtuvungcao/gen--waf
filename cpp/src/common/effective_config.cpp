#include "genwaf/effective_config.hpp"

#include <cctype>
#include <fstream>
#include <unordered_map>
#include <sstream>
#include <stdexcept>

namespace genwaf {

namespace {

std::string read_file(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open effective config: " + path);
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object };

  Type type = Type::Null;
  bool bool_value = false;
  long long number_value = 0;
  std::string string_value;
  std::vector<JsonValue> array_value;
  std::unordered_map<std::string, JsonValue> object_value;
};

class JsonParser {
 public:
  explicit JsonParser(const std::string& input) : input_(input) {}

  JsonValue Parse() {
    JsonValue value = ParseValue();
    SkipWhitespace();
    if (pos_ != input_.size()) {
      throw std::runtime_error("unexpected trailing characters in effective config");
    }
    return value;
  }

 private:
  const std::string& input_;
  std::size_t pos_ = 0;

  void SkipWhitespace() {
    while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
  }

  char Peek() const {
    if (pos_ >= input_.size()) {
      throw std::runtime_error("unexpected end of effective config");
    }
    return input_[pos_];
  }

  char Consume() {
    const char ch = Peek();
    ++pos_;
    return ch;
  }

  void Expect(char expected) {
    if (Consume() != expected) {
      throw std::runtime_error("unexpected token in effective config");
    }
  }

  JsonValue ParseValue() {
    SkipWhitespace();
    switch (Peek()) {
      case '{':
        return ParseObject();
      case '[':
        return ParseArray();
      case '"':
        return ParseString();
      case 't':
      case 'f':
        return ParseBool();
      case 'n':
        return ParseNull();
      default:
        return ParseNumber();
    }
  }

  JsonValue ParseObject() {
    JsonValue value;
    value.type = JsonValue::Type::Object;
    Expect('{');
    SkipWhitespace();
    if (Peek() == '}') {
      Consume();
      return value;
    }
    while (true) {
      JsonValue key = ParseString();
      SkipWhitespace();
      Expect(':');
      value.object_value.emplace(key.string_value, ParseValue());
      SkipWhitespace();
      const char ch = Consume();
      if (ch == '}') {
        return value;
      }
      if (ch != ',') {
        throw std::runtime_error("expected ',' or '}' in object");
      }
      SkipWhitespace();
    }
  }

  JsonValue ParseArray() {
    JsonValue value;
    value.type = JsonValue::Type::Array;
    Expect('[');
    SkipWhitespace();
    if (Peek() == ']') {
      Consume();
      return value;
    }
    while (true) {
      value.array_value.push_back(ParseValue());
      SkipWhitespace();
      const char ch = Consume();
      if (ch == ']') {
        return value;
      }
      if (ch != ',') {
        throw std::runtime_error("expected ',' or ']' in array");
      }
      SkipWhitespace();
    }
  }

  JsonValue ParseString() {
    JsonValue value;
    value.type = JsonValue::Type::String;
    Expect('"');
    while (true) {
      const char ch = Consume();
      if (ch == '"') {
        return value;
      }
      if (ch == '\\') {
        const char escaped = Consume();
        switch (escaped) {
          case '"':
          case '\\':
          case '/':
            value.string_value.push_back(escaped);
            break;
          case 'b':
            value.string_value.push_back('\b');
            break;
          case 'f':
            value.string_value.push_back('\f');
            break;
          case 'n':
            value.string_value.push_back('\n');
            break;
          case 'r':
            value.string_value.push_back('\r');
            break;
          case 't':
            value.string_value.push_back('\t');
            break;
          case 'u':
            for (int i = 0; i < 4; ++i) {
              Consume();
            }
            value.string_value.push_back('?');
            break;
          default:
            throw std::runtime_error("unsupported escape in effective config");
        }
        continue;
      }
      value.string_value.push_back(ch);
    }
  }

  JsonValue ParseBool() {
    JsonValue value;
    value.type = JsonValue::Type::Bool;
    if (input_.compare(pos_, 4, "true") == 0) {
      value.bool_value = true;
      pos_ += 4;
      return value;
    }
    if (input_.compare(pos_, 5, "false") == 0) {
      value.bool_value = false;
      pos_ += 5;
      return value;
    }
    throw std::runtime_error("invalid boolean in effective config");
  }

  JsonValue ParseNull() {
    if (input_.compare(pos_, 4, "null") != 0) {
      throw std::runtime_error("invalid null in effective config");
    }
    pos_ += 4;
    return JsonValue{};
  }

  JsonValue ParseNumber() {
    JsonValue value;
    value.type = JsonValue::Type::Number;
    std::size_t start = pos_;
    if (input_[pos_] == '-') {
      ++pos_;
    }
    while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
    if (pos_ < input_.size() && input_[pos_] == '.') {
      ++pos_;
      while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        ++pos_;
      }
    }
    value.number_value = std::stoll(input_.substr(start, pos_ - start));
    return value;
  }
};

const JsonValue* FindField(const JsonValue& root, const std::string& key) {
  if (root.type != JsonValue::Type::Object) {
    return nullptr;
  }
  const auto it = root.object_value.find(key);
  if (it == root.object_value.end()) {
    return nullptr;
  }
  return &it->second;
}

std::string extract_string(const JsonValue& root, const std::string& key, const std::string& fallback) {
  const JsonValue* value = FindField(root, key);
  if (!value || value->type != JsonValue::Type::String) {
    return fallback;
  }
  return value->string_value;
}

bool extract_bool(const JsonValue& root, const std::string& key, bool fallback) {
  const JsonValue* value = FindField(root, key);
  if (!value || value->type != JsonValue::Type::Bool) {
    return fallback;
  }
  return value->bool_value;
}

int extract_int(const JsonValue& root, const std::string& key, int fallback) {
  const JsonValue* value = FindField(root, key);
  if (!value || value->type != JsonValue::Type::Number) {
    return fallback;
  }
  return static_cast<int>(value->number_value);
}

std::vector<std::string> extract_string_array(const JsonValue& root, const std::string& key) {
  const JsonValue* value = FindField(root, key);
  if (!value || value->type != JsonValue::Type::Array) {
    return {};
  }
  std::vector<std::string> items;
  for (const auto& item : value->array_value) {
    if (item.type == JsonValue::Type::String) {
      items.push_back(item.string_value);
    }
  }
  return items;
}

}  // namespace

EffectiveConfig load_effective_config(const std::string& path) {
  const JsonValue body = JsonParser(read_file(path)).Parse();

  EffectiveConfig config;
  config.name = extract_string(body, "name", config.name);
  config.deployment = extract_string(body, "deployment", config.deployment);
  config.mode = extract_string(body, "mode", config.mode);
  config.default_action = extract_string(body, "default_action", config.default_action);
  config.proxy_engine = extract_string(body, "proxy_engine", config.proxy_engine);
  config.xdp_mode = extract_string(body, "xdp_mode", config.xdp_mode);
  config.xdp_interface = extract_string(body, "xdp_interface", config.xdp_interface);
  config.xdp_attach_mode = extract_string(body, "xdp_attach_mode", config.xdp_attach_mode);
  config.waf_engine = extract_string(body, "waf_engine", config.waf_engine);
  config.waf_mode = extract_string(body, "waf_mode", config.waf_mode);
  config.pow_provider = extract_string(body, "pow_provider", config.pow_provider);
  config.challenge_scope = extract_string(body, "challenge_scope", config.challenge_scope);
  config.response_action = extract_string(body, "response_action", config.response_action);
  config.decision_cache_ttl = extract_string(body, "decision_cache_ttl", config.decision_cache_ttl);
  config.sync_backend = extract_string(body, "sync_backend", config.sync_backend);
  config.http_parser = extract_string(body, "http_parser", config.http_parser);
  config.worker_model = extract_string(body, "worker_model", config.worker_model);
  config.rate_limit_backend = extract_string(body, "rate_limit_backend", config.rate_limit_backend);
  config.redis_address = extract_string(body, "redis_address", config.redis_address);
  config.redis_password = extract_string(body, "redis_password", config.redis_password);
  config.redis_prefix = extract_string(body, "redis_prefix", config.redis_prefix);

  config.auto_mode = extract_bool(body, "auto_mode", config.auto_mode);
  config.cloudflare_enabled = extract_bool(body, "cloudflare_enabled", config.cloudflare_enabled);
  config.proxy_dns = extract_bool(body, "proxy_dns", config.proxy_dns);
  config.hide_origin_ip = extract_bool(body, "hide_origin_ip", config.hide_origin_ip);
  config.lock_origin_to_cf = extract_bool(body, "lock_origin_to_cf", config.lock_origin_to_cf);
  config.cache_static = extract_bool(body, "cache_static", config.cache_static);
  config.trust_cf_headers = extract_bool(body, "trust_cf_headers", config.trust_cf_headers);
  config.xdp_enabled = extract_bool(body, "xdp_enabled", config.xdp_enabled);
  config.xdp_sync_from_controller = extract_bool(body, "xdp_sync_from_controller", config.xdp_sync_from_controller);
  config.allow_cf_only = extract_bool(body, "allow_cf_only", config.allow_cf_only);
  config.drop_invalid_packets = extract_bool(body, "drop_invalid_packets", config.drop_invalid_packets);
  config.per_ip_guard = extract_bool(body, "per_ip_guard", config.per_ip_guard);
  config.xdp_allowlist_cidrs = extract_string_array(body, "xdp_allowlist_cidrs");
  config.real_ip_from_edge_only = extract_bool(body, "real_ip_from_edge_only", config.real_ip_from_edge_only);
  config.cache_enabled = extract_bool(body, "cache_enabled", config.cache_enabled);
  config.keepalive = extract_bool(body, "keepalive", config.keepalive);
  config.waf_enabled = extract_bool(body, "waf_enabled", config.waf_enabled);
  config.crs_import_enabled = extract_bool(body, "crs_import_enabled", config.crs_import_enabled);
  config.rate_limit_enabled = extract_bool(body, "rate_limit_enabled", config.rate_limit_enabled);
  config.bot_defense_enabled = extract_bool(body, "bot_defense_enabled", config.bot_defense_enabled);
  config.js_challenge = extract_bool(body, "js_challenge", config.js_challenge);
  config.replay_protection = extract_bool(body, "replay_protection", config.replay_protection);
  config.pow_enabled = extract_bool(body, "pow_enabled", config.pow_enabled);
  config.behavior_enabled = extract_bool(body, "behavior_enabled", config.behavior_enabled);
  config.reputation_enabled = extract_bool(body, "reputation_enabled", config.reputation_enabled);
  config.learn_baseline = extract_bool(body, "learn_baseline", config.learn_baseline);
  config.fingerprint_tls = extract_bool(body, "fingerprint_tls", config.fingerprint_tls);
  config.fingerprint_http = extract_bool(body, "fingerprint_http", config.fingerprint_http);
  config.fingerprint_cookie = extract_bool(body, "fingerprint_cookie", config.fingerprint_cookie);
  config.fingerprint_session = extract_bool(body, "fingerprint_session", config.fingerprint_session);
  config.sitewide_challenge = extract_bool(body, "sitewide_challenge", config.sitewide_challenge);
  config.cache_aggressive = extract_bool(body, "cache_aggressive", config.cache_aggressive);
  config.cluster_sync_enabled = extract_bool(body, "cluster_sync_enabled", config.cluster_sync_enabled);
  config.config_push_enabled = extract_bool(body, "config_push_enabled", config.config_push_enabled);
  config.config_versioning = extract_bool(body, "config_versioning", config.config_versioning);
  config.staged_rollout = extract_bool(body, "staged_rollout", config.staged_rollout);
  config.shared_decisions = extract_bool(body, "shared_decisions", config.shared_decisions);
  config.redis_enabled = extract_bool(body, "redis_enabled", config.redis_enabled);
  config.postgres_enabled = extract_bool(body, "postgres_enabled", config.postgres_enabled);
  config.metrics_enabled = extract_bool(body, "metrics_enabled", config.metrics_enabled);
  config.logs_enabled = extract_bool(body, "logs_enabled", config.logs_enabled);
  config.traces_enabled = extract_bool(body, "traces_enabled", config.traces_enabled);
  config.dashboard_enabled = extract_bool(body, "dashboard_enabled", config.dashboard_enabled);
  config.zero_touch_bootstrap = extract_bool(body, "zero_touch_bootstrap", config.zero_touch_bootstrap);

  config.waf_paranoia_level = extract_int(body, "waf_paranoia_level", config.waf_paranoia_level);
  config.rate_limit_rps = extract_int(body, "rate_limit_rps", config.rate_limit_rps);
  config.rate_limit_burst = extract_int(body, "rate_limit_burst", config.rate_limit_burst);
  config.worker_threads = extract_int(body, "worker_threads", config.worker_threads);
  config.max_active_connections = extract_int(body, "max_active_connections", config.max_active_connections);
  config.max_keepalive_requests = extract_int(body, "max_keepalive_requests", config.max_keepalive_requests);
  config.cooldown_minutes = extract_int(body, "cooldown_minutes", config.cooldown_minutes);
  config.host_cpu_cores = extract_int(body, "host_cpu_cores", config.host_cpu_cores);
  config.host_memory_mb = extract_int(body, "host_memory_mb", config.host_memory_mb);
  config.listen_port = extract_int(body, "listen_port", config.listen_port);
  config.header_read_timeout_ms = extract_int(body, "header_read_timeout_ms", config.header_read_timeout_ms);
  config.max_request_bytes = extract_int(body, "max_request_bytes", config.max_request_bytes);
  config.max_response_cache_entries =
      extract_int(body, "max_response_cache_entries", config.max_response_cache_entries);
  config.upstream_connect_timeout_ms = extract_int(body, "upstream_connect_timeout_ms", config.upstream_connect_timeout_ms);
  config.upstream_read_timeout_ms = extract_int(body, "upstream_read_timeout_ms", config.upstream_read_timeout_ms);
  config.rate_limit_max_tracked_ips =
      extract_int(body, "rate_limit_max_tracked_ips", config.rate_limit_max_tracked_ips);
  config.challenge_difficulty = extract_int(body, "challenge_difficulty", config.challenge_difficulty);
  config.challenge_token_cache_entries =
      extract_int(body, "challenge_token_cache_entries", config.challenge_token_cache_entries);
  config.challenge_pass_ttl_seconds =
      extract_int(body, "challenge_pass_ttl_seconds", config.challenge_pass_ttl_seconds);
  config.max_decision_entries = extract_int(body, "max_decision_entries", config.max_decision_entries);
  config.shared_decision_ttl_seconds =
      extract_int(body, "shared_decision_ttl_seconds", config.shared_decision_ttl_seconds);
  config.decision_poll_interval_ms =
      extract_int(body, "decision_poll_interval_ms", config.decision_poll_interval_ms);
  config.node_heartbeat_interval_seconds =
      extract_int(body, "node_heartbeat_interval_seconds", config.node_heartbeat_interval_seconds);
  config.redis_db = extract_int(body, "redis_db", config.redis_db);
  config.observation_flush_interval_ms =
      extract_int(body, "observation_flush_interval_ms", config.observation_flush_interval_ms);
  config.observation_window_seconds =
      extract_int(body, "observation_window_seconds", config.observation_window_seconds);
  config.shared_rate_limit_threshold =
      extract_int(body, "shared_rate_limit_threshold", config.shared_rate_limit_threshold);
  config.shared_challenge_threshold =
      extract_int(body, "shared_challenge_threshold", config.shared_challenge_threshold);
  config.local_decision_path = extract_string(body, "local_decision_path", config.local_decision_path);
  config.local_observation_path = extract_string(body, "local_observation_path", config.local_observation_path);
  config.shared_rate_limit_path = extract_string(body, "shared_rate_limit_path", config.shared_rate_limit_path);
  config.sensitive_paths = extract_string_array(body, "sensitive_paths");
  config.backend_targets = extract_string_array(body, "backend_targets");
  config.virtual_host_rules = extract_string_array(body, "virtual_host_rules");

  return config;
}

std::string summarize(const EffectiveConfig& config) {
  std::ostringstream out;
  out << "name=" << config.name
      << " deployment=" << config.deployment
      << " mode=" << config.mode
      << " xdp_enabled=" << (config.xdp_enabled ? "true" : "false")
      << " xdp_sync_from_controller=" << (config.xdp_sync_from_controller ? "true" : "false")
      << " xdp_mode=" << config.xdp_mode
      << " xdp_allowlist_entries=" << config.xdp_allowlist_cidrs.size()
      << " waf=" << config.waf_engine
      << " waf_mode=" << config.waf_mode
      << " waf_paranoia_level=" << config.waf_paranoia_level
      << " rate_limit_backend=" << config.rate_limit_backend
      << " redis_enabled=" << (config.redis_enabled ? "true" : "false")
      << " rate_limit_rps=" << config.rate_limit_rps
      << " rate_limit_burst=" << config.rate_limit_burst
      << " challenge_scope=" << config.challenge_scope
      << " response_action=" << config.response_action
      << " shared_decisions=" << (config.shared_decisions ? "true" : "false")
      << " shared_rate_threshold=" << config.shared_rate_limit_threshold
      << " worker_threads=" << config.worker_threads
      << " max_active_connections=" << config.max_active_connections
      << " max_keepalive_requests=" << config.max_keepalive_requests
      << " host_cpu_cores=" << config.host_cpu_cores
      << " host_memory_mb=" << config.host_memory_mb;
  return out.str();
}

}  // namespace genwaf
