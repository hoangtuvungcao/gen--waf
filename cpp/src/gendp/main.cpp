#include "genwaf/effective_config.hpp"
#include "genwaf/waf_runtime.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <array>
#include <chrono>
#include <cctype>
#include <csignal>
#include <condition_variable>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <set>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

std::atomic<bool> g_running{true};

struct TokenBucket {
  double tokens = 0.0;
  Clock::time_point last_refill = Clock::now();
  Clock::time_point last_seen = Clock::now();
};

struct DecisionEntry {
  std::string decision;
  Clock::time_point expires_at = Clock::now();
};

struct SharedDecisionEntry {
  std::string fingerprint_id;
  std::string action;
  std::string reason;
  Clock::time_point expires_at = Clock::now();
};

struct UsedChallengeTokenEntry {
  Clock::time_point expires_at = Clock::now();
};

struct ObservationEntry {
  std::string fingerprint_id;
  std::string tls_fingerprint;
  std::string tls_fingerprint_source;
  int edge_bot_score = -1;
  std::string http_fingerprint;
  int requests = 0;
  int challenge_failures = 0;
  int sensitive_hits = 0;
  Clock::time_point last_seen = Clock::now();
};

struct FingerprintReputationEntry {
  std::string fingerprint_id;
  std::string tls_fingerprint;
  std::string tls_fingerprint_source;
  int edge_bot_score = -1;
  std::string http_fingerprint;
  int requests = 0;
  int challenge_failures = 0;
  int sensitive_hits = 0;
  int score = 0;
  Clock::time_point last_seen = Clock::now();
  Clock::time_point expires_at = Clock::now();
};

struct LocalPressureEntry {
  int score = 0;
  Clock::time_point last_seen = Clock::now();
  Clock::time_point expires_at = Clock::now();
};

struct SharedRateLimitEntry {
  int requests = 0;
  int challenge_failures = 0;
  int sensitive_hits = 0;
  int reputation_score = 0;
  int window_seconds = 0;
  Clock::time_point expires_at = Clock::now();
};

struct RequestContext {
  std::string method;
  std::string path;
  std::string version;
  std::string host;
  std::string body;
  std::unordered_map<std::string, std::string> headers;
  std::string socket_peer_ip;
  std::string client_ip;
  std::string tls_fingerprint;
  std::string tls_fingerprint_source;
  int edge_bot_score = -1;
  std::string http_fingerprint;
  std::string cookie_fingerprint;
  std::string session_fingerprint;
  std::string fingerprint_id;
  bool keep_alive = false;
};

struct ParsedHeaders {
  std::unordered_map<std::string, std::string> values;
  std::unordered_map<std::string, int> counts;
};

struct BackendTarget {
  std::string pool;
  std::string id;
  std::string address;
  std::string health_path = "/healthz";
  int health_interval_ms = 5000;
  int health_timeout_ms = 1000;
  int unhealthy_threshold = 2;
  int healthy_threshold = 2;
  int fail_timeout_ms = 10000;
  int retry_attempts = 1;
};

struct PathRoute {
  std::string prefix;
  std::string pool;
};

struct VirtualHostRoute {
  std::vector<std::string> domains;
  std::string default_pool;
  std::vector<PathRoute> path_routes;
};

struct Metrics {
  std::atomic<uint64_t> total_requests{0};
  std::atomic<uint64_t> blocked_requests{0};
  std::atomic<uint64_t> challenged_requests{0};
  std::atomic<uint64_t> rate_limited_requests{0};
  std::atomic<uint64_t> shed_connections{0};
  std::atomic<uint64_t> cache_hits{0};
  std::atomic<uint64_t> cache_misses{0};
};

struct CacheEntry {
  std::string body;
  Clock::time_point expires_at = Clock::now();
};

struct BackendState {
  bool healthy = true;
  int consecutive_failures = 0;
  int consecutive_successes = 0;
  Clock::time_point cooldown_until = Clock::time_point::min();
  Clock::time_point last_probe = Clock::time_point::min();
  std::string last_error;
};

struct RuntimeState {
  std::mutex bucket_mutex;
  std::unordered_map<std::string, TokenBucket> buckets;
  std::mutex decision_mutex;
  std::unordered_map<std::string, DecisionEntry> decisions;
  std::mutex challenge_token_mutex;
  std::unordered_map<std::string, UsedChallengeTokenEntry> used_challenge_tokens;
  std::mutex cluster_decision_mutex;
  std::unordered_map<std::string, SharedDecisionEntry> cluster_decisions;
  Clock::time_point next_cluster_decision_poll = Clock::time_point::min();
  std::time_t cluster_decision_mtime_sec = 0;
  long cluster_decision_mtime_nsec = 0;
  std::mutex shared_rate_limit_mutex;
  std::unordered_map<std::string, SharedRateLimitEntry> shared_rate_limits;
  Clock::time_point next_shared_rate_limit_poll = Clock::time_point::min();
  std::time_t shared_rate_limit_mtime_sec = 0;
  long shared_rate_limit_mtime_nsec = 0;
  std::mutex observation_mutex;
  std::unordered_map<std::string, ObservationEntry> observations;
  std::mutex local_pressure_mutex;
  std::unordered_map<std::string, LocalPressureEntry> local_pressure;
  std::mutex fingerprint_mutex;
  std::unordered_map<std::string, FingerprintReputationEntry> fingerprint_reputation;
  std::mutex cache_mutex;
  std::unordered_map<std::string, CacheEntry> cache;
  std::mutex log_mutex;
  Clock::time_point log_window_start = Clock::now();
  int emitted_logs_in_window = 0;
  int suppressed_logs_in_window = 0;
  std::atomic<int> active_connections{0};
  std::mutex rr_mutex;
  std::unordered_map<std::string, std::size_t> rr_index;
  std::unordered_map<std::string, std::string> pool_balance;
  std::unordered_map<std::string, std::vector<BackendTarget>> backend_pools;
  std::mutex backend_mutex;
  std::unordered_map<std::string, BackendState> backend_states;
  std::vector<BackendTarget> backend_catalog;
  std::vector<VirtualHostRoute> virtual_hosts;
  std::string challenge_secret;
  Metrics metrics;
};

struct ConnectionTask {
  int client_fd = -1;
  sockaddr_in client_addr{};
};

struct ConnectionQueue {
  std::mutex mutex;
  std::condition_variable cv;
  std::queue<ConnectionTask> tasks;
  bool stopping = false;
};

void log_if_enabled(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& message);
void trim_map_to_limit(std::unordered_map<std::string, CacheEntry>& entries, std::size_t limit);
void trim_map_to_limit(std::unordered_map<std::string, DecisionEntry>& entries, std::size_t limit);
void trim_map_to_limit(std::unordered_map<std::string, UsedChallengeTokenEntry>& entries, std::size_t limit);
void trim_map_to_limit(std::unordered_map<std::string, TokenBucket>& entries, std::size_t limit);
void trim_map_to_limit(std::unordered_map<std::string, ObservationEntry>& entries, std::size_t limit);
void trim_map_to_limit(std::unordered_map<std::string, LocalPressureEntry>& entries, std::size_t limit);
void trim_map_to_limit(std::unordered_map<std::string, FingerprintReputationEntry>& entries, std::size_t limit);
void refresh_cluster_decisions(RuntimeState& state, const genwaf::EffectiveConfig& config);
std::string now_iso();
long long epoch_millis();
bool path_is_sensitive(const genwaf::EffectiveConfig& config, const std::string& path);

std::string_view extract_arg(int argc, char** argv, std::string_view flag, std::string_view fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::string_view(argv[i]) == flag) {
      return argv[i + 1];
    }
  }
  return fallback;
}

int extract_port(int argc, char** argv, int fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::string_view(argv[i]) == "--port") {
      return std::stoi(argv[i + 1]);
    }
  }
  return fallback;
}

void handle_signal(int) {
  g_running = false;
}

std::string trim(std::string value) {
  while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
    value.pop_back();
  }
  std::size_t start = 0;
  while (start < value.size() && value[start] == ' ') {
    ++start;
  }
  return value.substr(start);
}

std::string ascii_lower(std::string value) {
  for (char& ch : value) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return value;
}

bool http_parser_debug_enabled() {
  static const bool enabled = []() {
    const char* value = std::getenv("GENWAF_DEBUG_HTTP_PARSER");
    if (value == nullptr) {
      return false;
    }
    const std::string lowered = ascii_lower(trim(value));
    return lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on";
  }();
  return enabled;
}

std::vector<std::string> split(const std::string& value, char sep) {
  std::vector<std::string> parts;
  std::stringstream ss(value);
  std::string item;
  while (std::getline(ss, item, sep)) {
    if (!item.empty()) {
      parts.push_back(item);
    }
  }
  return parts;
}

std::string strip_host_port(const std::string& host) {
  const auto pos = host.find(':');
  if (pos == std::string::npos) {
    return host;
  }
  return host.substr(0, pos);
}

std::string backend_key(const BackendTarget& target) {
  return target.pool + "|" + target.id + "|" + target.address;
}

std::string hex_u64(uint64_t value) {
  std::ostringstream out;
  out << std::hex << std::setw(16) << std::setfill('0') << value;
  return out.str();
}

uint64_t fnv1a64(const std::string& input) {
  uint64_t hash = 14695981039346656037ULL;
  for (unsigned char ch : input) {
    hash ^= static_cast<uint64_t>(ch);
    hash *= 1099511628211ULL;
  }
  return hash;
}

std::string hex_encode(const unsigned char* data, unsigned int len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(static_cast<std::size_t>(len) * 2);
  for (unsigned int i = 0; i < len; ++i) {
    out[static_cast<std::size_t>(i) * 2] = kHex[(data[i] >> 4) & 0x0F];
    out[static_cast<std::size_t>(i) * 2 + 1] = kHex[data[i] & 0x0F];
  }
  return out;
}

std::string hmac_sha256_hex(const std::string& secret, const std::string& payload) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  if (HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
           reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest, &digest_len) == nullptr) {
    return {};
  }
  return hex_encode(digest, digest_len);
}

bool timing_safe_equal(const std::string& left, const std::string& right) {
  if (left.size() != right.size()) {
    return false;
  }
  return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool has_leading_zero_nibbles(uint64_t value, int difficulty) {
  if (difficulty <= 0) {
    return true;
  }
  const int clamped = std::min(difficulty, 16);
  for (int i = 0; i < clamped; ++i) {
    const int shift = (15 - i) * 4;
    if (((value >> shift) & 0xFULL) != 0) {
      return false;
    }
  }
  return true;
}

std::string issue_secret() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  return hex_u64(dist(gen)) + hex_u64(dist(gen));
}

std::string escape_json(const std::string& value) {
  std::ostringstream out;
  for (char ch : value) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        out << ch;
        break;
    }
  }
  return out.str();
}

std::string escape_html(const std::string& value) {
  std::ostringstream out;
  for (char ch : value) {
    switch (ch) {
      case '&':
        out << "&amp;";
        break;
      case '<':
        out << "&lt;";
        break;
      case '>':
        out << "&gt;";
        break;
      case '"':
        out << "&quot;";
        break;
      case '\'':
        out << "&#39;";
        break;
      default:
        out << ch;
        break;
    }
  }
  return out.str();
}

std::size_t parse_content_length_value(const std::string& raw) {
  const std::string lowered = ascii_lower(raw);
  const std::string marker = "\r\ncontent-length:";
  auto pos = lowered.find(marker);
  if (pos == std::string::npos) {
    pos = lowered.find("\ncontent-length:");
  }
  if (pos == std::string::npos) {
    return 0;
  }
  pos = lowered.find(':', pos);
  if (pos == std::string::npos) {
    return 0;
  }
  ++pos;
  while (pos < raw.size() && raw[pos] == ' ') {
    ++pos;
  }
  std::size_t end = pos;
  while (end < raw.size() && std::isdigit(static_cast<unsigned char>(raw[end]))) {
    ++end;
  }
  if (end == pos) {
    return 0;
  }
  return static_cast<std::size_t>(std::stoul(raw.substr(pos, end - pos)));
}

bool header_has_chunked_transfer(const std::string& raw) {
  const std::string lowered = ascii_lower(raw);
  for (const std::string marker : {std::string("\r\ntransfer-encoding:"), std::string("\ntransfer-encoding:")}) {
    const auto pos = lowered.find(marker);
    if (pos == std::string::npos) {
      continue;
    }
    const auto value_begin = pos + marker.size();
    auto line_end = lowered.find("\r\n", value_begin);
    if (line_end == std::string::npos) {
      line_end = lowered.find('\n', value_begin);
    }
    const std::string value =
        trim(lowered.substr(value_begin, line_end == std::string::npos ? std::string::npos : line_end - value_begin));
    return value.find("chunked") != std::string::npos;
  }
  return false;
}

std::optional<std::size_t> chunked_message_end(const std::string& raw, std::size_t body_start, std::size_t limit) {
  std::size_t cursor = body_start;
  while (cursor < raw.size() && cursor < limit) {
    const auto line_end = raw.find("\r\n", cursor);
    if (line_end == std::string::npos) {
      return std::nullopt;
    }
    std::string size_token = raw.substr(cursor, line_end - cursor);
    const auto semicolon = size_token.find(';');
    if (semicolon != std::string::npos) {
      size_token = size_token.substr(0, semicolon);
    }
    size_token = trim(size_token);
    if (size_token.empty()) {
      return std::nullopt;
    }
    char* end = nullptr;
    const unsigned long chunk_size = std::strtoul(size_token.c_str(), &end, 16);
    if (end == nullptr || *end != '\0') {
      return std::nullopt;
    }
    cursor = line_end + 2;
    if (chunk_size == 0) {
      if (raw.compare(cursor, 2, "\r\n") == 0) {
        return cursor + 2;
      }
      const auto trailer_end = raw.find("\r\n\r\n", cursor);
      if (trailer_end == std::string::npos) {
        return std::nullopt;
      }
      return trailer_end + 4;
    }
    const std::size_t chunk_end = cursor + static_cast<std::size_t>(chunk_size);
    if (chunk_end + 2 > raw.size() || chunk_end + 2 > limit) {
      return std::nullopt;
    }
    if (raw.compare(chunk_end, 2, "\r\n") != 0) {
      return std::nullopt;
    }
    cursor = chunk_end + 2;
  }
  return std::nullopt;
}

std::optional<std::string> decode_chunked_body(const std::string& body) {
  const auto debug_reject = [&](std::string_view reason) -> std::optional<std::string> {
    if (http_parser_debug_enabled()) {
      std::cerr << "[gendp][http-parser] chunked decode failed: " << reason
                << " body=\"" << escape_json(body) << "\"" << std::endl;
    }
    return std::nullopt;
  };
  std::string decoded;
  std::size_t cursor = 0;
  while (cursor < body.size()) {
    const auto line_end = body.find("\r\n", cursor);
    if (line_end == std::string::npos) {
      return debug_reject("missing_size_delimiter");
    }
    std::string size_token = body.substr(cursor, line_end - cursor);
    const auto semicolon = size_token.find(';');
    if (semicolon != std::string::npos) {
      size_token = size_token.substr(0, semicolon);
    }
    size_token = trim(size_token);
    char* end = nullptr;
    const unsigned long chunk_size = std::strtoul(size_token.c_str(), &end, 16);
    if (end == nullptr || *end != '\0') {
      return debug_reject("invalid_chunk_size");
    }
    cursor = line_end + 2;
    if (chunk_size == 0) {
      return decoded;
    }
    const std::size_t chunk_end = cursor + static_cast<std::size_t>(chunk_size);
    if (chunk_end + 2 > body.size() || body.compare(chunk_end, 2, "\r\n") != 0) {
      return debug_reject("missing_chunk_terminator");
    }
    decoded.append(body, cursor, static_cast<std::size_t>(chunk_size));
    cursor = chunk_end + 2;
  }
  return debug_reject("missing_terminal_zero_chunk");
}

std::optional<std::string> read_http_request(int client_fd, int max_request_bytes) {
  constexpr std::size_t kChunkSize = 8192;
  const std::size_t limit = static_cast<std::size_t>(std::max(1024, max_request_bytes));

  std::string raw;
  raw.reserve(kChunkSize);

  while (raw.size() < limit) {
    char buffer[kChunkSize];
    const ssize_t received = recv(client_fd, buffer, sizeof(buffer), 0);
    if (received <= 0) {
      if (raw.empty()) {
        return std::nullopt;
      }
      break;
    }

    raw.append(buffer, static_cast<std::size_t>(received));

    const auto header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) {
      continue;
    }

    const std::string header_block = raw.substr(0, header_end + 4);
    if (header_has_chunked_transfer(header_block)) {
      if (const auto end = chunked_message_end(raw, header_end + 4, limit); end.has_value()) {
        raw.resize(*end);
        return raw;
      }
      continue;
    }

    const std::size_t content_length = parse_content_length_value(header_block);
    const std::size_t expected = header_end + 4 + content_length;
    if (raw.size() >= expected) {
      raw.resize(expected);
      return raw;
    }
  }

  if (raw.empty()) {
    return std::nullopt;
  }
  return raw;
}

bool send_all(int fd, const std::string& payload) {
  std::size_t offset = 0;
  while (offset < payload.size()) {
    const ssize_t sent = send(fd, payload.data() + offset, payload.size() - offset, 0);
    if (sent <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(sent);
  }
  return true;
}

bool is_http_token(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  for (const unsigned char ch : value) {
    if (std::isalnum(ch)) {
      continue;
    }
    switch (ch) {
      case '!':
      case '#':
      case '$':
      case '%':
      case '&':
      case '\'':
      case '*':
      case '+':
      case '-':
      case '.':
      case '^':
      case '_':
      case '`':
      case '|':
      case '~':
        continue;
      default:
        return false;
    }
  }
  return true;
}

bool is_valid_header_value(std::string_view value) {
  for (const unsigned char ch : value) {
    if (ch == '\t') {
      continue;
    }
    if (ch < 32 || ch == 127) {
      return false;
    }
  }
  return true;
}

std::optional<ParsedHeaders> parse_headers(const std::vector<std::string>& lines) {
  ParsedHeaders parsed;
  for (std::size_t i = 1; i < lines.size(); ++i) {
    if (lines[i].empty()) {
      continue;
    }
    const auto pos = lines[i].find(':');
    if (pos == std::string::npos) {
      return std::nullopt;
    }
    const std::string name = ascii_lower(trim(lines[i].substr(0, pos)));
    if (!is_http_token(name)) {
      return std::nullopt;
    }
    const std::string value = trim(lines[i].substr(pos + 1));
    if (!is_valid_header_value(value)) {
      return std::nullopt;
    }
    parsed.counts[name]++;
    auto it = parsed.values.find(name);
    if (it == parsed.values.end()) {
      parsed.values[name] = value;
    } else if (it->second != value) {
      parsed.values[name] = value;
    }
  }
  return parsed;
}

std::unordered_map<std::string, std::string> parse_cookie_header(const std::string& value) {
  std::unordered_map<std::string, std::string> cookies;
  std::stringstream ss(value);
  std::string item;
  while (std::getline(ss, item, ';')) {
    const auto pos = item.find('=');
    if (pos == std::string::npos) {
      continue;
    }
    cookies[trim(item.substr(0, pos))] = trim(item.substr(pos + 1));
  }
  return cookies;
}

std::string url_decode(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '+' ) {
      out.push_back(' ');
      continue;
    }
    if (value[i] == '%' && i + 2 < value.size()) {
      const auto hex = value.substr(i + 1, 2);
      char* end = nullptr;
      const long v = std::strtol(hex.c_str(), &end, 16);
      if (end != nullptr && *end == '\0') {
        out.push_back(static_cast<char>(v));
        i += 2;
        continue;
      }
    }
    out.push_back(value[i]);
  }
  return out;
}

std::optional<std::string> parse_content_length_header(const std::unordered_map<std::string, std::string>& headers) {
  const auto it = headers.find("content-length");
  if (it == headers.end()) {
    return std::nullopt;
  }
  if (it->second.empty()) {
    return std::nullopt;
  }
  for (const unsigned char ch : it->second) {
    if (!std::isdigit(ch)) {
      return std::nullopt;
    }
  }
  return it->second;
}

bool contains_ctl_or_space(std::string_view value) {
  for (const unsigned char ch : value) {
    if (ch <= 32 || ch == 127) {
      return true;
    }
  }
  return false;
}

bool normalize_request_target(RequestContext& req) {
  if (req.path.empty() || contains_ctl_or_space(req.path)) {
    return false;
  }
  if (req.path == "*") {
    return req.method == "OPTIONS";
  }
  if (req.path.rfind("http://", 0) == 0 || req.path.rfind("https://", 0) == 0) {
    const auto scheme_sep = req.path.find("://");
    if (scheme_sep == std::string::npos) {
      return false;
    }
    const auto authority_begin = scheme_sep + 3;
    const auto path_begin = req.path.find('/', authority_begin);
    const std::string authority =
        path_begin == std::string::npos ? req.path.substr(authority_begin) : req.path.substr(authority_begin, path_begin - authority_begin);
    if (authority.empty()) {
      return false;
    }
    if (req.host.empty()) {
      req.host = strip_host_port(authority);
    }
    req.path = path_begin == std::string::npos ? "/" : req.path.substr(path_begin);
    return !req.path.empty() && req.path[0] == '/';
  }
  return req.path[0] == '/';
}

std::unordered_map<std::string, std::string> parse_form_body(const std::string& body) {
  std::unordered_map<std::string, std::string> fields;
  std::stringstream ss(body);
  std::string item;
  while (std::getline(ss, item, '&')) {
    const auto pos = item.find('=');
    if (pos == std::string::npos) {
      continue;
    }
    fields[url_decode(item.substr(0, pos))] = url_decode(item.substr(pos + 1));
  }
  return fields;
}

std::string read_text_file(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    return {};
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::string extract_json_string_field(const std::string& body, const std::string& key) {
  const std::string token = "\"" + key + "\"";
  const auto key_pos = body.find(token);
  if (key_pos == std::string::npos) {
    return {};
  }
  const auto colon = body.find(':', key_pos + token.size());
  if (colon == std::string::npos) {
    return {};
  }
  auto pos = colon + 1;
  while (pos < body.size() && body[pos] == ' ') {
    ++pos;
  }
  if (pos >= body.size() || body[pos] != '"') {
    return {};
  }
  const auto end = body.find('"', pos + 1);
  if (end == std::string::npos) {
    return {};
  }
  return body.substr(pos + 1, end - pos - 1);
}

long long extract_json_int_field(const std::string& body, const std::string& key) {
  const std::string token = "\"" + key + "\"";
  const auto key_pos = body.find(token);
  if (key_pos == std::string::npos) {
    return 0;
  }
  const auto colon = body.find(':', key_pos + token.size());
  if (colon == std::string::npos) {
    return 0;
  }
  auto pos = colon + 1;
  while (pos < body.size() && body[pos] == ' ') {
    ++pos;
  }
  auto end = pos;
  while (end < body.size() && std::isdigit(static_cast<unsigned char>(body[end]))) {
    ++end;
  }
  if (end == pos) {
    return 0;
  }
  return std::stoll(body.substr(pos, end - pos));
}

std::unordered_map<std::string, SharedDecisionEntry> parse_shared_decisions_file(const std::string& path) {
  std::unordered_map<std::string, SharedDecisionEntry> parsed;
  const std::string body = read_text_file(path);
  if (body.empty()) {
    return parsed;
  }

  const auto decisions_key = body.find("\"decisions\"");
  if (decisions_key == std::string::npos) {
    return parsed;
  }
  const auto array_begin = body.find('[', decisions_key);
  const auto array_end = body.find(']', array_begin);
  if (array_begin == std::string::npos || array_end == std::string::npos || array_end <= array_begin) {
    return parsed;
  }

  const auto now_wall = std::chrono::system_clock::now();
  const auto now_steady = Clock::now();
  std::size_t cursor = array_begin + 1;
  while (cursor < array_end) {
    const auto object_begin = body.find('{', cursor);
    if (object_begin == std::string::npos || object_begin >= array_end) {
      break;
    }
    const auto object_end = body.find('}', object_begin);
    if (object_end == std::string::npos || object_end > array_end) {
      break;
    }
    const std::string object = body.substr(object_begin, object_end - object_begin + 1);
    const std::string client_ip = extract_json_string_field(object, "client_ip");
    const std::string fingerprint_id = extract_json_string_field(object, "fingerprint_id");
    const std::string action = extract_json_string_field(object, "action");
    const std::string reason = extract_json_string_field(object, "reason");
    const long long expires_at_unix = extract_json_int_field(object, "expires_at_unix");
    if ((!client_ip.empty() || !fingerprint_id.empty()) && !action.empty() && expires_at_unix > 0) {
      const auto expires_wall = std::chrono::system_clock::time_point(std::chrono::seconds(expires_at_unix));
      if (expires_wall > now_wall) {
        SharedDecisionEntry entry;
        entry.fingerprint_id = fingerprint_id;
        entry.action = action;
        entry.reason = reason;
        entry.expires_at = now_steady + std::chrono::duration_cast<Clock::duration>(expires_wall - now_wall);
        if (!client_ip.empty()) {
          parsed["ip:" + client_ip] = entry;
        }
        if (!fingerprint_id.empty()) {
          parsed["fp:" + fingerprint_id] = entry;
        }
      }
    }
    cursor = object_end + 1;
  }
  return parsed;
}

std::unordered_map<std::string, SharedRateLimitEntry> parse_shared_rate_limits_file(const std::string& path) {
  std::unordered_map<std::string, SharedRateLimitEntry> parsed;
  const std::string body = read_text_file(path);
  if (body.empty()) {
    return parsed;
  }

  const auto observations_key = body.find("\"observations\"");
  if (observations_key == std::string::npos) {
    return parsed;
  }
  const auto array_begin = body.find('[', observations_key);
  const auto array_end = body.find(']', array_begin);
  if (array_begin == std::string::npos || array_end == std::string::npos || array_end <= array_begin) {
    return parsed;
  }

  const auto now_wall = std::chrono::system_clock::now();
  const auto now_steady = Clock::now();
  std::size_t cursor = array_begin + 1;
  while (cursor < array_end) {
    const auto object_begin = body.find('{', cursor);
    if (object_begin == std::string::npos || object_begin >= array_end) {
      break;
    }
    const auto object_end = body.find('}', object_begin);
    if (object_end == std::string::npos || object_end > array_end) {
      break;
    }
    const std::string object = body.substr(object_begin, object_end - object_begin + 1);
    const std::string client_ip = extract_json_string_field(object, "client_ip");
    const long long expires_at_unix = extract_json_int_field(object, "expires_at");
    const int requests = static_cast<int>(extract_json_int_field(object, "requests"));
    if (!client_ip.empty() && requests > 0 && expires_at_unix > 0) {
      const auto expires_wall = std::chrono::system_clock::time_point(std::chrono::seconds(expires_at_unix));
      if (expires_wall > now_wall) {
        SharedRateLimitEntry entry;
        entry.requests = requests;
        entry.challenge_failures = static_cast<int>(extract_json_int_field(object, "challenge_failures"));
        entry.sensitive_hits = static_cast<int>(extract_json_int_field(object, "sensitive_hits"));
        entry.reputation_score = static_cast<int>(extract_json_int_field(object, "reputation_score"));
        entry.window_seconds = static_cast<int>(extract_json_int_field(object, "window_seconds"));
        entry.expires_at = now_steady + std::chrono::duration_cast<Clock::duration>(expires_wall - now_wall);
        parsed[client_ip] = entry;
      }
    }
    cursor = object_end + 1;
  }
  return parsed;
}

void refresh_cluster_decisions(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  if (!config.cluster_sync_enabled || !config.shared_decisions || config.local_decision_path.empty()) {
    return;
  }
  const auto now = Clock::now();
  {
    std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
    if (now < state.next_cluster_decision_poll) {
      return;
    }
    state.next_cluster_decision_poll = now + std::chrono::milliseconds(std::max(100, config.decision_poll_interval_ms));
  }

  struct stat st {};
  if (stat(config.local_decision_path.c_str(), &st) != 0) {
    std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
    state.cluster_decisions.clear();
    state.cluster_decision_mtime_sec = 0;
    state.cluster_decision_mtime_nsec = 0;
    return;
  }
  {
    std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
    if (state.cluster_decision_mtime_sec == st.st_mtim.tv_sec &&
        state.cluster_decision_mtime_nsec == st.st_mtim.tv_nsec) {
      return;
    }
  }

  auto parsed = parse_shared_decisions_file(config.local_decision_path);
  std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
  state.cluster_decisions = std::move(parsed);
  state.cluster_decision_mtime_sec = st.st_mtim.tv_sec;
  state.cluster_decision_mtime_nsec = st.st_mtim.tv_nsec;
}

void refresh_shared_rate_limits(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  if (!config.cluster_sync_enabled || config.shared_rate_limit_path.empty()) {
    return;
  }
  const auto now = Clock::now();
  {
    std::lock_guard<std::mutex> lock(state.shared_rate_limit_mutex);
    if (now < state.next_shared_rate_limit_poll) {
      return;
    }
    state.next_shared_rate_limit_poll = now + std::chrono::milliseconds(std::max(100, config.decision_poll_interval_ms));
  }

  struct stat st {};
  if (stat(config.shared_rate_limit_path.c_str(), &st) != 0) {
    std::lock_guard<std::mutex> lock(state.shared_rate_limit_mutex);
    state.shared_rate_limits.clear();
    state.shared_rate_limit_mtime_sec = 0;
    state.shared_rate_limit_mtime_nsec = 0;
    return;
  }
  {
    std::lock_guard<std::mutex> lock(state.shared_rate_limit_mutex);
    if (state.shared_rate_limit_mtime_sec == st.st_mtim.tv_sec &&
        state.shared_rate_limit_mtime_nsec == st.st_mtim.tv_nsec) {
      return;
    }
  }

  auto parsed = parse_shared_rate_limits_file(config.shared_rate_limit_path);
  std::lock_guard<std::mutex> lock(state.shared_rate_limit_mutex);
  state.shared_rate_limits = std::move(parsed);
  state.shared_rate_limit_mtime_sec = st.st_mtim.tv_sec;
  state.shared_rate_limit_mtime_nsec = st.st_mtim.tv_nsec;
}

std::optional<SharedDecisionEntry> cluster_decision_for_request(RuntimeState& state, const RequestContext& req) {
  std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
  const auto now = Clock::now();
  const auto by_ip = state.cluster_decisions.find("ip:" + req.client_ip);
  if (by_ip != state.cluster_decisions.end()) {
    if (now > by_ip->second.expires_at) {
      state.cluster_decisions.erase(by_ip);
    } else {
      return by_ip->second;
    }
  }
  if (!req.fingerprint_id.empty()) {
    const auto by_fp = state.cluster_decisions.find("fp:" + req.fingerprint_id);
    if (by_fp != state.cluster_decisions.end()) {
      if (now > by_fp->second.expires_at) {
        state.cluster_decisions.erase(by_fp);
      } else {
        return by_fp->second;
      }
    }
  }
  return std::nullopt;
}

std::optional<SharedRateLimitEntry> shared_rate_limit_for_ip(RuntimeState& state, const std::string& client_ip) {
  std::lock_guard<std::mutex> lock(state.shared_rate_limit_mutex);
  const auto it = state.shared_rate_limits.find(client_ip);
  if (it == state.shared_rate_limits.end()) {
    return std::nullopt;
  }
  if (Clock::now() > it->second.expires_at) {
    state.shared_rate_limits.erase(it);
    return std::nullopt;
  }
  return it->second;
}

bool has_cloudflare_markers(const RequestContext& req);
bool has_chunked_transfer(const RequestContext& req);
std::string trusted_edge_marker(const RequestContext& req);
bool trusted_edge_metadata(const genwaf::EffectiveConfig& config, const RequestContext& req);

std::optional<RequestContext> parse_request(const std::string& raw, const genwaf::EffectiveConfig& config, const std::string& peer_ip) {
  const auto reject = [&](std::string_view reason) -> std::optional<RequestContext> {
    if (http_parser_debug_enabled()) {
      std::cerr << "[gendp][http-parser] rejected: " << reason << std::endl;
    }
    return std::nullopt;
  };
  const auto header_end = raw.find("\r\n\r\n");
  const std::string head = header_end == std::string::npos ? raw : raw.substr(0, header_end);
  const std::string body = header_end == std::string::npos ? "" : raw.substr(header_end + 4);

  std::vector<std::string> lines;
  std::istringstream stream(head);
  std::string line;
  while (std::getline(stream, line)) {
    if (line == "\r" || line.empty()) {
      break;
    }
    lines.push_back(trim(line));
  }
  if (lines.empty() || lines.size() > 128) {
    return reject("line_count");
  }

  std::istringstream request_line(lines[0]);
  RequestContext req;
  request_line >> req.method >> req.path >> req.version;
  std::string trailing;
  request_line >> trailing;
  if (!trailing.empty() || !is_http_token(req.method) || req.method.size() > 32 || req.path.empty() ||
      (req.version != "HTTP/1.0" && req.version != "HTTP/1.1")) {
    return reject("request_line");
  }
  const auto headers = parse_headers(lines);
  if (!headers.has_value()) {
    return reject("headers_invalid");
  }
  if (headers->counts.contains("host") && headers->counts.at("host") > 1) {
    return reject("duplicate_host");
  }
  if (headers->counts.contains("content-length") && headers->counts.at("content-length") > 1) {
    return reject("duplicate_content_length");
  }
  if (headers->counts.contains("transfer-encoding") && headers->counts.at("transfer-encoding") > 1) {
    return reject("duplicate_transfer_encoding");
  }
  req.headers = headers->values;
  req.body = body;
  req.socket_peer_ip = peer_ip;

  const auto host = req.headers.find("host");
  if (host != req.headers.end()) {
    req.host = strip_host_port(host->second);
  }
  if (!normalize_request_target(req)) {
    return reject("request_target");
  }
  if (req.version == "HTTP/1.1" && req.host.empty()) {
    return reject("missing_host");
  }
  if (req.headers.contains("transfer-encoding") && req.headers.contains("content-length")) {
    return reject("te_and_cl");
  }
  if (const auto content_length = parse_content_length_header(req.headers); content_length.has_value()) {
    std::size_t declared_length = 0;
    try {
      declared_length = static_cast<std::size_t>(std::stoull(*content_length));
    } catch (...) {
      return reject("content_length_parse");
    }
    if (declared_length != req.body.size()) {
      return reject("content_length_mismatch");
    }
  }
  if (has_chunked_transfer(req)) {
    if (ascii_lower(req.headers["transfer-encoding"]) != "chunked") {
      return reject("transfer_encoding_not_chunked_only");
    }
    const auto decoded = decode_chunked_body(req.body);
    if (!decoded.has_value()) {
      return reject("chunked_decode");
    }
    req.body = decoded.value();
    req.headers.erase("transfer-encoding");
    req.headers["content-length"] = std::to_string(req.body.size());
  }

  auto it = req.headers.find("connection");
  const std::string connection_value = it == req.headers.end() ? "" : ascii_lower(it->second);
  const bool close_requested = connection_value == "close";
  const bool keepalive_requested = connection_value == "keep-alive";
  req.keep_alive = config.keepalive && !close_requested && (req.version == "HTTP/1.1" || keepalive_requested);

  req.client_ip = peer_ip;
  if (trusted_edge_metadata(config, req)) {
    const auto local_edge_ip = req.headers.find("x-genwaf-client-ip");
    const auto cf = req.headers.find("cf-connecting-ip");
    if (local_edge_ip != req.headers.end() && !local_edge_ip->second.empty()) {
      req.client_ip = local_edge_ip->second;
    } else if (cf != req.headers.end() && !cf->second.empty()) {
      req.client_ip = cf->second;
    }
  }
  return req;
}

void build_routing(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  std::set<std::string> seen_backends;
  for (const auto& entry : config.backend_targets) {
    BackendTarget target;
    target.health_path = "/healthz";
    target.health_interval_ms = 5000;
    target.health_timeout_ms = 1000;
    target.unhealthy_threshold = 2;
    target.healthy_threshold = 2;
    target.fail_timeout_ms = 10000;
    target.retry_attempts = 1;
    std::string balance = "round_robin";
    int weight = 1;
    for (const auto& part : split(entry, '|')) {
      const auto pos = part.find('=');
      if (pos == std::string::npos) {
        continue;
      }
      const auto key = part.substr(0, pos);
      const auto value = part.substr(pos + 1);
      if (key == "pool") {
        target.pool = value;
      } else if (key == "balance") {
        balance = value;
      } else if (key == "id") {
        target.id = value;
      } else if (key == "address") {
        target.address = value;
      } else if (key == "health_path") {
        target.health_path = value;
      } else if (key == "health_interval_ms") {
        target.health_interval_ms = std::max(500, std::stoi(value));
      } else if (key == "health_timeout_ms") {
        target.health_timeout_ms = std::max(100, std::stoi(value));
      } else if (key == "unhealthy_threshold") {
        target.unhealthy_threshold = std::max(1, std::stoi(value));
      } else if (key == "healthy_threshold") {
        target.healthy_threshold = std::max(1, std::stoi(value));
      } else if (key == "fail_timeout_ms") {
        target.fail_timeout_ms = std::max(1000, std::stoi(value));
      } else if (key == "retry_attempts") {
        target.retry_attempts = std::max(0, std::stoi(value));
      } else if (key == "weight") {
        weight = std::max(1, std::stoi(value));
      }
    }
    state.pool_balance[target.pool] = balance;
    const std::string key = backend_key(target);
    if (seen_backends.insert(key).second) {
      state.backend_catalog.push_back(target);
      state.backend_states[key] = BackendState{};
    }
    for (int i = 0; i < weight; ++i) {
      state.backend_pools[target.pool].push_back(target);
    }
  }

  for (const auto& entry : config.virtual_host_rules) {
    VirtualHostRoute route;
    for (const auto& part : split(entry, '|')) {
      const auto pos = part.find('=');
      if (pos == std::string::npos) {
        continue;
      }
      const auto key = part.substr(0, pos);
      const auto value = part.substr(pos + 1);
      if (key == "domains") {
        route.domains = split(value, ',');
      } else if (key == "default_pool") {
        route.default_pool = value;
      } else if (key == "paths" && !value.empty()) {
        for (const auto& path_part : split(value, ',')) {
          const auto rule_pos = path_part.find(':');
          if (rule_pos == std::string::npos) {
            continue;
          }
          route.path_routes.push_back(PathRoute{
              .prefix = path_part.substr(0, rule_pos),
              .pool = path_part.substr(rule_pos + 1),
          });
        }
      }
    }
    state.virtual_hosts.push_back(route);
  }
}

std::optional<BackendTarget> select_backend(RuntimeState& state, const RequestContext& req) {
  for (const auto& host : state.virtual_hosts) {
    bool match = false;
    for (const auto& domain : host.domains) {
      if (domain == "*" || domain == req.host) {
        match = true;
        break;
      }
    }
    if (!match) {
      continue;
    }

    std::string pool = host.default_pool;
    std::size_t longest_match = 0;
    for (const auto& rule : host.path_routes) {
      if (req.path.rfind(rule.prefix, 0) == 0 && rule.prefix.size() >= longest_match) {
        pool = rule.pool;
        longest_match = rule.prefix.size();
      }
    }

    auto pool_it = state.backend_pools.find(pool);
    if (pool_it == state.backend_pools.end() || pool_it->second.empty()) {
      return std::nullopt;
    }

    const auto balance_it = state.pool_balance.find(pool);
    const std::string balance = balance_it == state.pool_balance.end() ? "round_robin" : balance_it->second;
    const auto& targets = pool_it->second;

    auto is_healthy = [&](const BackendTarget& target) {
      std::lock_guard<std::mutex> health_lock(state.backend_mutex);
      const auto it = state.backend_states.find(backend_key(target));
      if (it == state.backend_states.end()) {
        return true;
      }
      return it->second.healthy;
    };

    std::vector<BackendTarget> candidates;
    for (const auto& target : targets) {
      if (is_healthy(target)) {
        candidates.push_back(target);
      }
    }
    if (candidates.empty()) {
      candidates = targets;
    }

    std::lock_guard<std::mutex> lock(state.rr_mutex);
    if (balance == "ip_hash") {
      const std::size_t hashed = std::hash<std::string>{}(req.client_ip);
      return candidates[hashed % candidates.size()];
    }

    auto& index = state.rr_index[pool];
    const BackendTarget selected = candidates[index % candidates.size()];
    index = (index + 1) % candidates.size();
    return selected;
  }
  return std::nullopt;
}

enum class BackendTransition {
  None,
  BecameHealthy,
  BecameUnhealthy,
};

BackendTransition mark_backend_result(RuntimeState& state, const BackendTarget& target, bool success,
                                      const std::string& reason) {
  std::lock_guard<std::mutex> lock(state.backend_mutex);
  auto& status = state.backend_states[backend_key(target)];
  const auto now = Clock::now();
  const bool was_healthy = status.healthy;
  if (success) {
    status.consecutive_failures = 0;
    status.consecutive_successes++;
    status.last_error.clear();
    if (!status.healthy && status.consecutive_successes >= target.healthy_threshold) {
      status.healthy = true;
      status.cooldown_until = Clock::time_point::min();
      return was_healthy ? BackendTransition::None : BackendTransition::BecameHealthy;
    }
    return BackendTransition::None;
  }

  status.consecutive_successes = 0;
  status.consecutive_failures++;
  status.last_error = reason;
  if (status.consecutive_failures >= target.unhealthy_threshold) {
    status.healthy = false;
    status.cooldown_until = now + std::chrono::milliseconds(target.fail_timeout_ms);
    if (was_healthy) {
      return BackendTransition::BecameUnhealthy;
    }
  }
  return BackendTransition::None;
}

bool connect_with_timeout(int sock, const sockaddr* addr, socklen_t addrlen, int timeout_ms) {
  const int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    return false;
  }

  const int rc = connect(sock, addr, addrlen);
  if (rc == 0) {
    fcntl(sock, F_SETFL, flags);
    return true;
  }
  if (errno != EINPROGRESS) {
    fcntl(sock, F_SETFL, flags);
    return false;
  }

  fd_set writefds;
  FD_ZERO(&writefds);
  FD_SET(sock, &writefds);

  timeval timeout{};
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  const int selected = select(sock + 1, nullptr, &writefds, nullptr, &timeout);
  if (selected <= 0) {
    fcntl(sock, F_SETFL, flags);
    return false;
  }

  int err = 0;
  socklen_t len = sizeof(err);
  if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
    fcntl(sock, F_SETFL, flags);
    return false;
  }

  fcntl(sock, F_SETFL, flags);
  return true;
}

struct RedisReply {
  enum class Type { SimpleString, Error, Integer, BulkString, Array, Nil };
  Type type = Type::Nil;
  long long integer = 0;
  std::string string;
  std::vector<RedisReply> array;
};

std::optional<std::pair<std::string, std::string>> split_host_port(const std::string& address) {
  if (address.empty()) {
    return std::nullopt;
  }
  if (address.front() == '[') {
    const auto end = address.find(']');
    if (end == std::string::npos || end + 2 > address.size() || address[end + 1] != ':') {
      return std::nullopt;
    }
    return std::make_pair(address.substr(1, end - 1), address.substr(end + 2));
  }
  const auto pos = address.rfind(':');
  if (pos == std::string::npos) {
    return std::nullopt;
  }
  return std::make_pair(address.substr(0, pos), address.substr(pos + 1));
}

bool read_exact(int fd, std::string& out, std::size_t bytes) {
  out.clear();
  out.reserve(bytes);
  while (out.size() < bytes) {
    char buffer[4096];
    const std::size_t remaining = bytes - out.size();
    const ssize_t received = recv(fd, buffer, std::min<std::size_t>(sizeof(buffer), remaining), 0);
    if (received <= 0) {
      return false;
    }
    out.append(buffer, static_cast<std::size_t>(received));
  }
  return true;
}

bool read_line_crlf(int fd, std::string& line) {
  line.clear();
  char ch = '\0';
  while (true) {
    const ssize_t received = recv(fd, &ch, 1, 0);
    if (received <= 0) {
      return false;
    }
    if (ch == '\r') {
      const ssize_t next = recv(fd, &ch, 1, 0);
      if (next <= 0 || ch != '\n') {
        return false;
      }
      return true;
    }
    line.push_back(ch);
    if (line.size() > 65536) {
      return false;
    }
  }
}

std::optional<RedisReply> read_redis_reply(int fd) {
  char type = '\0';
  if (recv(fd, &type, 1, 0) != 1) {
    return std::nullopt;
  }

  RedisReply reply;
  std::string line;
  switch (type) {
    case '+':
      if (!read_line_crlf(fd, line)) {
        return std::nullopt;
      }
      reply.type = RedisReply::Type::SimpleString;
      reply.string = line;
      return reply;
    case '-':
      if (!read_line_crlf(fd, line)) {
        return std::nullopt;
      }
      reply.type = RedisReply::Type::Error;
      reply.string = line;
      return reply;
    case ':':
      if (!read_line_crlf(fd, line)) {
        return std::nullopt;
      }
      reply.type = RedisReply::Type::Integer;
      reply.integer = std::stoll(line);
      return reply;
    case '$': {
      if (!read_line_crlf(fd, line)) {
        return std::nullopt;
      }
      const long long bulk_size = std::stoll(line);
      if (bulk_size < 0) {
        reply.type = RedisReply::Type::Nil;
        return reply;
      }
      std::string body;
      if (!read_exact(fd, body, static_cast<std::size_t>(bulk_size) + 2)) {
        return std::nullopt;
      }
      reply.type = RedisReply::Type::BulkString;
      reply.string = body.substr(0, static_cast<std::size_t>(bulk_size));
      return reply;
    }
    case '*': {
      if (!read_line_crlf(fd, line)) {
        return std::nullopt;
      }
      const int count = std::stoi(line);
      if (count < 0) {
        reply.type = RedisReply::Type::Nil;
        return reply;
      }
      reply.type = RedisReply::Type::Array;
      reply.array.reserve(static_cast<std::size_t>(count));
      for (int i = 0; i < count; ++i) {
        const auto item = read_redis_reply(fd);
        if (!item.has_value()) {
          return std::nullopt;
        }
        reply.array.push_back(std::move(item.value()));
      }
      return reply;
    }
    default:
      return std::nullopt;
  }
}

std::string encode_redis_command(const std::vector<std::string>& parts) {
  std::ostringstream out;
  out << "*" << parts.size() << "\r\n";
  for (const auto& part : parts) {
    out << "$" << part.size() << "\r\n" << part << "\r\n";
  }
  return out.str();
}

class RedisRateLimiterClient {
 public:
  std::optional<bool> Allow(const genwaf::EffectiveConfig& config, const std::string& client_ip, int rate_limit_rps,
                            int rate_limit_burst) {
    if (!config.redis_enabled || config.redis_address.empty()) {
      return std::nullopt;
    }
    if (!EnsureConnected(config)) {
      return std::nullopt;
    }

    static const std::string kScript =
        "local key=KEYS[1] "
        "local now_ms=tonumber(ARGV[1]) "
        "local rate_per_ms=tonumber(ARGV[2]) "
        "local burst=tonumber(ARGV[3]) "
        "local ttl_ms=tonumber(ARGV[4]) "
        "local request_tokens=tonumber(ARGV[5]) "
        "local data=redis.call('HMGET', key, 'tokens', 'last') "
        "local tokens=tonumber(data[1]) "
        "local last=tonumber(data[2]) "
        "if not tokens then tokens=burst end "
        "if not last then last=now_ms end "
        "if now_ms > last then "
        "  tokens=math.min(burst, tokens + ((now_ms - last) * rate_per_ms)) "
        "  last=now_ms "
        "end "
        "if tokens < request_tokens then "
        "  redis.call('HMSET', key, 'tokens', tokens, 'last', last) "
        "  redis.call('PEXPIRE', key, ttl_ms) "
        "  return {0, math.floor(tokens)} "
        "end "
        "tokens=tokens-request_tokens "
        "redis.call('HMSET', key, 'tokens', tokens, 'last', last) "
        "redis.call('PEXPIRE', key, ttl_ms) "
        "return {1, math.floor(tokens)}";

    const long long now_ms = epoch_millis();
    const double refill_per_ms = static_cast<double>(std::max(1, rate_limit_rps)) / 1000.0;
    const int ttl_ms = std::max(5000, (std::max(1, rate_limit_burst) * 4000) / std::max(1, rate_limit_rps));
    const std::string redis_prefix = config.redis_prefix.empty() ? "genwaf" : config.redis_prefix;
    const std::string key = redis_prefix + ":rl:" + config.name + ":" + client_ip;
    const std::vector<std::string> command = {
        "EVAL", kScript, "1", key, std::to_string(now_ms),
        std::to_string(refill_per_ms), std::to_string(std::max(1, rate_limit_burst)),
        std::to_string(ttl_ms), "1"};
    const auto reply = SendCommand(command);
    if (!reply.has_value() || reply->type != RedisReply::Type::Array || reply->array.empty()) {
      Close();
      return std::nullopt;
    }
    if (reply->array[0].type != RedisReply::Type::Integer) {
      Close();
      return std::nullopt;
    }
    return reply->array[0].integer == 1;
  }

 private:
  int fd_ = -1;
  std::string last_endpoint_;
  std::string last_password_;
  int last_db_ = 0;

  void Close() {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
  }

  bool EnsureConnected(const genwaf::EffectiveConfig& config) {
    if (fd_ >= 0 && last_endpoint_ == config.redis_address && last_password_ == config.redis_password &&
        last_db_ == config.redis_db) {
      return true;
    }
    Close();

    const auto endpoint = split_host_port(config.redis_address);
    if (!endpoint.has_value()) {
      return false;
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(endpoint->first.c_str(), endpoint->second.c_str(), &hints, &result) != 0) {
      return false;
    }

    int connected_fd = -1;
    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
      connected_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (connected_fd < 0) {
        continue;
      }
      timeval timeout{};
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      setsockopt(connected_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(connected_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      if (connect_with_timeout(connected_fd, rp->ai_addr, rp->ai_addrlen, 1000)) {
        break;
      }
      close(connected_fd);
      connected_fd = -1;
    }
    freeaddrinfo(result);
    if (connected_fd < 0) {
      return false;
    }

    fd_ = connected_fd;
    last_endpoint_ = config.redis_address;
    last_password_ = config.redis_password;
    last_db_ = config.redis_db;

    if (!config.redis_password.empty()) {
      const auto auth = SendCommand({"AUTH", config.redis_password});
      if (!auth.has_value() || auth->type == RedisReply::Type::Error) {
        Close();
        return false;
      }
    }
    if (config.redis_db > 0) {
      const auto select = SendCommand({"SELECT", std::to_string(config.redis_db)});
      if (!select.has_value() || select->type == RedisReply::Type::Error) {
        Close();
        return false;
      }
    }
    return true;
  }

  std::optional<RedisReply> SendCommand(const std::vector<std::string>& parts) {
    if (fd_ < 0) {
      return std::nullopt;
    }
    const std::string payload = encode_redis_command(parts);
    if (!send_all(fd_, payload)) {
      Close();
      return std::nullopt;
    }
    const auto reply = read_redis_reply(fd_);
    if (!reply.has_value() || reply->type == RedisReply::Type::Error) {
      Close();
      return std::nullopt;
    }
    return reply;
  }
};

std::optional<std::string> proxy_to_backend(const genwaf::EffectiveConfig& config, const BackendTarget& backend, const RequestContext& req) {
  const auto pos = backend.address.rfind(':');
  if (pos == std::string::npos) {
    return std::nullopt;
  }
  const std::string host = backend.address.substr(0, pos);
  const std::string port = backend.address.substr(pos + 1);

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) {
    return std::nullopt;
  }

  int sock = -1;
  for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0) {
      continue;
    }

    timeval timeout{};
    timeout.tv_sec = config.upstream_read_timeout_ms / 1000;
    timeout.tv_usec = (config.upstream_read_timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect_with_timeout(sock, rp->ai_addr, rp->ai_addrlen, config.upstream_connect_timeout_ms)) {
      break;
    }
    close(sock);
    sock = -1;
  }
  freeaddrinfo(result);
  if (sock < 0) {
    return std::nullopt;
  }

  std::ostringstream outbound;
  outbound << req.method << " " << req.path << " " << (req.version.empty() ? "HTTP/1.1" : req.version) << "\r\n";
  outbound << "Host: " << req.host << "\r\n";
  outbound << "X-Forwarded-For: " << req.client_ip << "\r\n";
  outbound << "X-Real-IP: " << req.client_ip << "\r\n";
  outbound << "X-Forwarded-Host: " << req.host << "\r\n";
  outbound << "X-Forwarded-Proto: http\r\n";
  outbound << "Connection: close\r\n";
  for (const auto& [key, value] : req.headers) {
    if (key == "host" || key == "connection" || key == "content-length" || key == "transfer-encoding" ||
        key == "x-edge-verified" || key == "cf-connecting-ip" || key == "x-forwarded-for" ||
        key == "x-forwarded-host" || key == "x-forwarded-proto" || key == "x-real-ip") {
      continue;
    }
    outbound << key << ": " << value << "\r\n";
  }
  outbound << "Content-Length: " << req.body.size() << "\r\n";
  outbound << "\r\n";
  outbound << req.body;

  const std::string payload = outbound.str();
  if (!send_all(sock, payload)) {
    close(sock);
    return std::nullopt;
  }

  std::string response;
  char buffer[8192];
  while (true) {
    const ssize_t received = recv(sock, buffer, sizeof(buffer), 0);
    if (received <= 0) {
      break;
    }
    response.append(buffer, static_cast<std::size_t>(received));
  }
  close(sock);

  if (response.empty()) {
    return std::nullopt;
  }
  return response;
}

bool probe_backend_once(const BackendTarget& backend) {
  const auto pos = backend.address.rfind(':');
  if (pos == std::string::npos) {
    return false;
  }
  const std::string host = backend.address.substr(0, pos);
  const std::string port = backend.address.substr(pos + 1);

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) {
    return false;
  }

  int sock = -1;
  for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0) {
      continue;
    }
    timeval timeout{};
    timeout.tv_sec = backend.health_timeout_ms / 1000;
    timeout.tv_usec = (backend.health_timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect_with_timeout(sock, rp->ai_addr, rp->ai_addrlen, backend.health_timeout_ms)) {
      break;
    }
    close(sock);
    sock = -1;
  }
  freeaddrinfo(result);
  if (sock < 0) {
    return false;
  }

  std::ostringstream request;
  request << "GET " << backend.health_path << " HTTP/1.1\r\n";
  request << "Host: " << host << "\r\n";
  request << "Connection: close\r\n\r\n";
  if (!send_all(sock, request.str())) {
    close(sock);
    return false;
  }

  char buffer[1024];
  const ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
  close(sock);
  if (received <= 0) {
    return false;
  }
  const std::string response(buffer, static_cast<std::size_t>(received));
  return response.rfind("HTTP/1.1 2", 0) == 0 || response.rfind("HTTP/1.0 2", 0) == 0 ||
         response.rfind("HTTP/1.1 3", 0) == 0 || response.rfind("HTTP/1.0 3", 0) == 0;
}

void health_loop(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  while (g_running) {
    for (const auto& target : state.backend_catalog) {
      if (!g_running) {
        break;
      }

      bool should_probe = false;
      {
        std::lock_guard<std::mutex> lock(state.backend_mutex);
        auto& status = state.backend_states[backend_key(target)];
        const auto now = Clock::now();
        if (status.last_probe == Clock::time_point::min() ||
            now - status.last_probe >= std::chrono::milliseconds(target.health_interval_ms)) {
          status.last_probe = now;
          should_probe = true;
        }
      }
      if (!should_probe) {
        continue;
      }

      const bool ok = probe_backend_once(target);
      const BackendTransition transition = mark_backend_result(state, target, ok, ok ? "" : "active health check failed");
      if (transition == BackendTransition::BecameUnhealthy) {
        log_if_enabled(state, config, "health probe marked backend unhealthy: " + target.address);
      } else if (transition == BackendTransition::BecameHealthy) {
        log_if_enabled(state, config, "backend recovered after health checks: " + target.address);
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

int parse_ttl_seconds(const std::string& value) {
  if (value.empty()) {
    return 60;
  }
  try {
    if (value.back() == 's') {
      return std::stoi(value.substr(0, value.size() - 1));
    }
    if (value.back() == 'm') {
      return std::stoi(value.substr(0, value.size() - 1)) * 60;
    }
  } catch (...) {
    return 60;
  }
  return 60;
}

bool path_is_sensitive(const genwaf::EffectiveConfig& config, const std::string& path) {
  for (const auto& prefix : config.sensitive_paths) {
    if (!prefix.empty() && path.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return false;
}

std::string request_user_agent(const RequestContext& req) {
  const auto it = req.headers.find("user-agent");
  if (it == req.headers.end()) {
    return "";
  }
  return it->second;
}

std::string challenge_signature(const RuntimeState& state, const RequestContext& req, const std::string& path,
                                const std::string& seed, long long expires_at, int difficulty) {
  const std::string payload = state.challenge_secret + "|challenge|" + req.client_ip + "|" + request_user_agent(req) +
                              "|" + path + "|" + seed + "|" + std::to_string(expires_at) + "|" +
                              std::to_string(difficulty);
  return hmac_sha256_hex(state.challenge_secret, payload);
}

std::string captcha_signature(const RuntimeState& state, const RequestContext& req, const std::string& path,
                              long long issued_at_ms, long long expires_at_ms) {
  const std::string payload = state.challenge_secret + "|captcha|" + req.client_ip + "|" + request_user_agent(req) +
                              "|" + path + "|" + std::to_string(issued_at_ms) + "|" + std::to_string(expires_at_ms);
  return hmac_sha256_hex(state.challenge_secret, payload);
}

std::string pass_signature(const RuntimeState& state, const RequestContext& req, long long expires_at) {
  const std::string payload = state.challenge_secret + "|pass|" + req.client_ip + "|" + request_user_agent(req) + "|" +
                              std::to_string(expires_at);
  return hmac_sha256_hex(state.challenge_secret, payload);
}

std::string challenge_token_key(const std::string& kind, const std::string& sig) {
  return kind + "|" + sig;
}

bool consume_challenge_token(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& token_key,
                             Clock::time_point expires_at) {
  if (!config.replay_protection) {
    return true;
  }

  std::lock_guard<std::mutex> lock(state.challenge_token_mutex);
  const auto now = Clock::now();
  for (auto it = state.used_challenge_tokens.begin(); it != state.used_challenge_tokens.end();) {
    if (now > it->second.expires_at) {
      it = state.used_challenge_tokens.erase(it);
      continue;
    }
    ++it;
  }

  const auto existing = state.used_challenge_tokens.find(token_key);
  if (existing != state.used_challenge_tokens.end() && now <= existing->second.expires_at) {
    return false;
  }

  const std::size_t limit = static_cast<std::size_t>(std::max(64, config.challenge_token_cache_entries));
  if (state.used_challenge_tokens.size() >= limit && existing == state.used_challenge_tokens.end()) {
    trim_map_to_limit(state.used_challenge_tokens, limit - 1);
  }
  state.used_challenge_tokens[token_key] = UsedChallengeTokenEntry{.expires_at = expires_at};
  return true;
}

std::string issue_pass_cookie(const genwaf::EffectiveConfig& config, const RuntimeState& state, const RequestContext& req) {
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
  const long long expires_at = now + std::max(30, config.challenge_pass_ttl_seconds);
  const std::string sig = pass_signature(state, req, expires_at);
  std::ostringstream cookie;
  cookie << "genwaf_pass=" << expires_at << "." << sig << "; Max-Age=" << std::max(30, config.challenge_pass_ttl_seconds)
         << "; Path=/; HttpOnly; SameSite=Lax";
  return cookie.str();
}

bool has_valid_pass_cookie(const genwaf::EffectiveConfig& config, const RuntimeState& state, const RequestContext& req) {
  if (!config.bot_defense_enabled) {
    return false;
  }
  const auto cookie_it = req.headers.find("cookie");
  if (cookie_it == req.headers.end()) {
    return false;
  }
  const auto cookies = parse_cookie_header(cookie_it->second);
  const auto pass_it = cookies.find("genwaf_pass");
  if (pass_it == cookies.end()) {
    return false;
  }
  const auto dot = pass_it->second.find('.');
  if (dot == std::string::npos) {
    return false;
  }
  try {
    const long long expires_at = std::stoll(pass_it->second.substr(0, dot));
    const std::string sig = pass_it->second.substr(dot + 1);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
    if (expires_at <= now) {
      return false;
    }
    return timing_safe_equal(sig, pass_signature(state, req, expires_at));
  } catch (...) {
    return false;
  }
}

bool has_chunked_transfer(const RequestContext& req) {
  const auto it = req.headers.find("transfer-encoding");
  if (it == req.headers.end()) {
    return false;
  }
  return ascii_lower(it->second).find("chunked") != std::string::npos;
}

bool ipv4_in_cidr(const std::string& ip, const char* cidr, int prefix) {
  in_addr parsed_ip{};
  in_addr parsed_base{};
  if (inet_pton(AF_INET, ip.c_str(), &parsed_ip) != 1 || inet_pton(AF_INET, cidr, &parsed_base) != 1) {
    return false;
  }
  const uint32_t ip_value = ntohl(parsed_ip.s_addr);
  const uint32_t base_value = ntohl(parsed_base.s_addr);
  if (prefix <= 0) {
    return true;
  }
  const uint32_t mask = prefix >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix));
  return (ip_value & mask) == (base_value & mask);
}

bool peer_is_local_or_private(const std::string& peer_ip) {
  if (peer_ip.empty()) {
    return false;
  }
  if (peer_ip == "::1" || peer_ip == "localhost") {
    return true;
  }
  return ipv4_in_cidr(peer_ip, "127.0.0.0", 8) || ipv4_in_cidr(peer_ip, "10.0.0.0", 8) ||
         ipv4_in_cidr(peer_ip, "172.16.0.0", 12) || ipv4_in_cidr(peer_ip, "192.168.0.0", 16);
}

bool has_cloudflare_markers(const RequestContext& req) {
  const auto cf_ip = req.headers.find("cf-connecting-ip");
  const auto cf_ray = req.headers.find("cf-ray");
  return cf_ip != req.headers.end() && !cf_ip->second.empty() && cf_ray != req.headers.end() && !cf_ray->second.empty();
}

std::string trusted_edge_marker(const RequestContext& req) {
  const auto verified = req.headers.find("x-edge-verified");
  if (verified == req.headers.end()) {
    return "";
  }
  const std::string value = ascii_lower(trim(verified->second));
  if (value == "cloudflare") {
    return value;
  }
  if (value == "genedge" && peer_is_local_or_private(req.socket_peer_ip)) {
    return value;
  }
  return "";
}

bool trusted_edge_metadata(const genwaf::EffectiveConfig& config, const RequestContext& req) {
  if (!trusted_edge_marker(req).empty()) {
    return true;
  }
  return config.cloudflare_enabled && config.trust_cf_headers && has_cloudflare_markers(req);
}

bool edge_verified(const genwaf::EffectiveConfig& config, const RequestContext& req) {
  if (!config.lock_origin_to_cf && !config.allow_cf_only) {
    return true;
  }
  return trusted_edge_metadata(config, req);
}

std::string header_value(const RequestContext& req, const std::string& name) {
  const auto it = req.headers.find(name);
  if (it == req.headers.end()) {
    return "";
  }
  return it->second;
}

std::string canonicalize_header_value(const RequestContext& req, const std::string& name) {
  return ascii_lower(trim(header_value(req, name)));
}

std::string session_cookie_value(const RequestContext& req) {
  const auto cookie_it = req.headers.find("cookie");
  if (cookie_it == req.headers.end()) {
    return "";
  }
  const auto cookies = parse_cookie_header(cookie_it->second);
  static const std::array<std::string_view, 6> kSessionNames = {
      "session", "sessionid", "sessid", "phpseid", "phpsessid", "connect.sid"};
  for (const auto& name : kSessionNames) {
    const auto it = cookies.find(std::string(name));
    if (it != cookies.end() && !it->second.empty()) {
      return it->second;
    }
  }
  return "";
}

int clamp_int(int value, int min_value, int max_value) {
  return std::max(min_value, std::min(max_value, value));
}

std::optional<int> parse_edge_bot_score(const RequestContext& req) {
  if (trusted_edge_marker(req).empty() && !has_cloudflare_markers(req)) {
    return std::nullopt;
  }
  static const std::array<std::string_view, 3> kScoreHeaders = {
      "x-genwaf-bot-score", "cf-bot-score", "x-bot-score"};
  for (const auto& header : kScoreHeaders) {
    const std::string value = trim(header_value(req, std::string(header)));
    if (value.empty()) {
      continue;
    }
    bool digits_only = true;
    for (const unsigned char ch : value) {
      if (!std::isdigit(ch)) {
        digits_only = false;
        break;
      }
    }
    if (!digits_only) {
      continue;
    }
    try {
      return clamp_int(std::stoi(value), 0, 100);
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

struct EdgeTLSFingerprint {
  std::string value;
  std::string source;
};

std::optional<EdgeTLSFingerprint> extract_edge_tls_fingerprint(const RequestContext& req) {
  if (trusted_edge_marker(req).empty() && !has_cloudflare_markers(req)) {
    return std::nullopt;
  }
  static const std::array<std::pair<std::string_view, std::string_view>, 6> kTLSHeaders = {{
      {"x-genwaf-tls-fingerprint", "genwaf"},
      {"cf-ja4", "cf-ja4"},
      {"x-ja4", "ja4"},
      {"cf-ja3", "cf-ja3"},
      {"x-ja3", "ja3"},
      {"x-tls-fingerprint", "generic"},
  }};
  for (const auto& [header, source] : kTLSHeaders) {
    const std::string value = ascii_lower(trim(header_value(req, std::string(header))));
    if (!value.empty()) {
      return EdgeTLSFingerprint{.value = value, .source = std::string(source)};
    }
  }
  return std::nullopt;
}

void apply_fingerprint_decay(FingerprintReputationEntry& entry, Clock::time_point now) {
  if (now <= entry.last_seen) {
    return;
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_seen).count();
  if (elapsed <= 0) {
    return;
  }
  const int score_decay = static_cast<int>(elapsed / 20);
  const int request_decay = static_cast<int>(elapsed / 45);
  const int fail_decay = static_cast<int>(elapsed / 90);
  const int sensitive_decay = static_cast<int>(elapsed / 120);
  entry.score = std::max(0, entry.score - score_decay);
  entry.requests = std::max(0, entry.requests - request_decay);
  entry.challenge_failures = std::max(0, entry.challenge_failures - fail_decay);
  entry.sensitive_hits = std::max(0, entry.sensitive_hits - sensitive_decay);
}

std::string cookie_name_fingerprint(const RequestContext& req) {
  const auto cookie_it = req.headers.find("cookie");
  if (cookie_it == req.headers.end()) {
    return "";
  }
  const auto cookies = parse_cookie_header(cookie_it->second);
  if (cookies.empty()) {
    return "";
  }
  std::vector<std::string> names;
  names.reserve(cookies.size());
  for (const auto& [name, _] : cookies) {
    names.push_back(ascii_lower(name));
  }
  std::sort(names.begin(), names.end());
  std::ostringstream out;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i > 0) {
      out << ';';
    }
    out << names[i];
  }
  return out.str();
}

void populate_request_fingerprint(RuntimeState& state, const genwaf::EffectiveConfig& config, RequestContext& req) {
  std::vector<std::string> components;

  if (config.fingerprint_http) {
    std::ostringstream http;
    http << canonicalize_header_value(req, "user-agent")
         << "|" << canonicalize_header_value(req, "accept")
         << "|" << canonicalize_header_value(req, "accept-language")
         << "|" << canonicalize_header_value(req, "accept-encoding")
         << "|" << canonicalize_header_value(req, "sec-fetch-site")
         << "|" << canonicalize_header_value(req, "sec-fetch-mode")
         << "|" << canonicalize_header_value(req, "sec-fetch-dest")
         << "|" << canonicalize_header_value(req, "sec-ch-ua")
         << "|" << canonicalize_header_value(req, "sec-ch-ua-platform")
         << "|" << canonicalize_header_value(req, "sec-ch-ua-mobile");
    if (http.str().find_first_not_of('|') != std::string::npos) {
      req.http_fingerprint = hex_u64(fnv1a64(http.str()));
      components.push_back("http:" + req.http_fingerprint);
    }
  }

  if (config.fingerprint_tls && edge_verified(config, req)) {
    if (const auto edge_tls = extract_edge_tls_fingerprint(req); edge_tls.has_value()) {
      req.tls_fingerprint = edge_tls->value;
      req.tls_fingerprint_source = edge_tls->source;
      components.push_back("tls:" + req.tls_fingerprint_source + ":" + req.tls_fingerprint);
    }
  }

  if (edge_verified(config, req)) {
    if (const auto bot_score = parse_edge_bot_score(req); bot_score.has_value()) {
      req.edge_bot_score = *bot_score;
    }
  }

  if (config.fingerprint_cookie) {
    const std::string cookie_names = cookie_name_fingerprint(req);
    if (!cookie_names.empty()) {
      req.cookie_fingerprint = hex_u64(fnv1a64(cookie_names));
      components.push_back("cookie:" + req.cookie_fingerprint);
    }
  }

  if (config.fingerprint_session) {
    const std::string session_value = session_cookie_value(req);
    if (!session_value.empty()) {
      req.session_fingerprint = hex_u64(fnv1a64(session_value));
      components.push_back("session:" + req.session_fingerprint);
    }
  }

  if (components.empty()) {
    return;
  }

  std::ostringstream payload;
  payload << config.name;
  for (const auto& component : components) {
    payload << "|" << component;
  }
  req.fingerprint_id = hmac_sha256_hex(state.challenge_secret, payload.str()).substr(0, 32);
}

void adjust_fingerprint_reputation(RuntimeState& state, const genwaf::EffectiveConfig& config, const RequestContext& req,
                                   int delta, bool challenge_failure) {
  if (!config.behavior_enabled || !config.reputation_enabled || req.fingerprint_id.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock(state.fingerprint_mutex);
  const auto now = Clock::now();
  for (auto it = state.fingerprint_reputation.begin(); it != state.fingerprint_reputation.end();) {
    if (now > it->second.expires_at) {
      it = state.fingerprint_reputation.erase(it);
      continue;
    }
    ++it;
  }
  auto& entry = state.fingerprint_reputation[req.fingerprint_id];
  apply_fingerprint_decay(entry, now);
  entry.fingerprint_id = req.fingerprint_id;
  entry.tls_fingerprint = req.tls_fingerprint;
  entry.tls_fingerprint_source = req.tls_fingerprint_source;
  entry.edge_bot_score = req.edge_bot_score;
  entry.http_fingerprint = req.http_fingerprint;
  entry.requests++;
  if (challenge_failure) {
    entry.challenge_failures++;
  }
  if (path_is_sensitive(config, req.path)) {
    entry.sensitive_hits++;
  }
  if (req.edge_bot_score >= 80) {
    delta -= 3;
  } else if (req.edge_bot_score >= 50) {
    delta -= 1;
  } else if (req.edge_bot_score >= 0 && req.edge_bot_score <= 10) {
    delta += 3;
  }
  entry.last_seen = now;
  entry.expires_at = now + std::chrono::minutes(20);
  entry.score = std::max(0, std::min(400, entry.score + delta));
  const std::size_t limit = static_cast<std::size_t>(std::max(128, config.rate_limit_max_tracked_ips / 4));
  if (state.fingerprint_reputation.size() > limit) {
    trim_map_to_limit(state.fingerprint_reputation, limit);
  }
}

std::optional<FingerprintReputationEntry> fingerprint_reputation_for_request(RuntimeState& state, const RequestContext& req) {
  if (req.fingerprint_id.empty()) {
    return std::nullopt;
  }
  std::lock_guard<std::mutex> lock(state.fingerprint_mutex);
  const auto it = state.fingerprint_reputation.find(req.fingerprint_id);
  if (it == state.fingerprint_reputation.end()) {
    return std::nullopt;
  }
  if (Clock::now() > it->second.expires_at) {
    state.fingerprint_reputation.erase(it);
    return std::nullopt;
  }
  apply_fingerprint_decay(it->second, Clock::now());
  it->second.last_seen = Clock::now();
  return it->second;
}

std::string fingerprint_progressive_action(RuntimeState& state, const RequestContext& req) {
  const auto entry = fingerprint_reputation_for_request(state, req);
  if (!entry.has_value()) {
    return "";
  }
  if (entry->score >= 26 || entry->challenge_failures >= 6) {
    return "temporary_ban";
  }
  if (entry->score >= 12 || entry->challenge_failures >= 3) {
    return "pow_challenge";
  }
  if (entry->score >= 5) {
    return "soft_challenge";
  }
  return "";
}

bool allow_by_rate_limit(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& client_ip) {
  if (!config.rate_limit_enabled) {
    return true;
  }

  if (config.rate_limit_backend == "redis_native") {
    thread_local RedisRateLimiterClient redis_client;
    if (const auto allowed = redis_client.Allow(config, client_ip, config.rate_limit_rps, config.rate_limit_burst);
        allowed.has_value()) {
      return *allowed;
    }
  }

  int effective_rps = config.rate_limit_rps;
  int effective_burst = config.rate_limit_burst;
  if (config.rate_limit_backend == "cluster_shared") {
    if (const auto shared = shared_rate_limit_for_ip(state, client_ip); shared.has_value()) {
      if (shared->requests >= std::max(1, config.shared_rate_limit_threshold)) {
        return false;
      }
      if (shared->requests >= std::max(1, config.shared_challenge_threshold) || shared->reputation_score >= 90) {
        effective_rps = std::max(1, effective_rps / 2);
        effective_burst = std::max(1, std::min(effective_burst, std::max(1, config.shared_rate_limit_threshold - shared->requests)));
      }
    }
  }

  std::lock_guard<std::mutex> lock(state.bucket_mutex);
  if (state.buckets.size() >= static_cast<std::size_t>(std::max(1, config.rate_limit_max_tracked_ips)) &&
      state.buckets.find(client_ip) == state.buckets.end()) {
    trim_map_to_limit(state.buckets, static_cast<std::size_t>(std::max(1, config.rate_limit_max_tracked_ips - 1)));
  }
  auto& bucket = state.buckets[client_ip];
  if (bucket.tokens == 0.0) {
    bucket.tokens = static_cast<double>(effective_burst);
    bucket.last_refill = Clock::now();
  }

  const auto now = Clock::now();
  bucket.last_seen = now;
  const std::chrono::duration<double> elapsed = now - bucket.last_refill;
  bucket.tokens = std::min<double>(effective_burst, bucket.tokens + elapsed.count() * effective_rps);
  bucket.last_refill = now;

  if (bucket.tokens < 1.0) {
    return false;
  }
  bucket.tokens -= 1.0;
  return true;
}

void trim_map_to_limit(std::unordered_map<std::string, LocalPressureEntry>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

void trim_map_to_limit(std::unordered_map<std::string, FingerprintReputationEntry>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

void adjust_local_pressure(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& client_ip, int delta) {
  std::lock_guard<std::mutex> lock(state.local_pressure_mutex);
  const auto now = Clock::now();
  for (auto it = state.local_pressure.begin(); it != state.local_pressure.end();) {
    if (now > it->second.expires_at) {
      it = state.local_pressure.erase(it);
      continue;
    }
    ++it;
  }
  auto& entry = state.local_pressure[client_ip];
  entry.last_seen = now;
  entry.expires_at = now + std::chrono::minutes(15);
  entry.score = std::max(0, std::min(100, entry.score + delta));
  trim_map_to_limit(state.local_pressure, static_cast<std::size_t>(std::max(128, config.rate_limit_max_tracked_ips / 4)));
}

void clear_local_pressure(RuntimeState& state, const std::string& client_ip) {
  std::lock_guard<std::mutex> lock(state.local_pressure_mutex);
  state.local_pressure.erase(client_ip);
}

std::string local_progressive_action(RuntimeState& state, const std::string& client_ip) {
  std::lock_guard<std::mutex> lock(state.local_pressure_mutex);
  const auto it = state.local_pressure.find(client_ip);
  if (it == state.local_pressure.end()) {
    return "";
  }
  if (Clock::now() > it->second.expires_at) {
    state.local_pressure.erase(it);
    return "";
  }
  if (it->second.score >= 18) {
    return "temporary_ban";
  }
  if (it->second.score >= 8) {
    return "pow_challenge";
  }
  if (it->second.score >= 3) {
    return "soft_challenge";
  }
  return "";
}

int progressive_action_strength(const std::string& action) {
  if (action == "temporary_ban") {
    return 3;
  }
  if (action == "pow_challenge") {
    return 2;
  }
  if (action == "soft_challenge") {
    return 1;
  }
  return 0;
}

std::string stronger_progressive_action(const std::string& left, const std::string& right) {
  return progressive_action_strength(left) >= progressive_action_strength(right) ? left : right;
}

std::optional<std::string> cached_decision(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& client_ip) {
  if (!config.behavior_enabled) {
    return std::nullopt;
  }

  std::lock_guard<std::mutex> lock(state.decision_mutex);
  const auto it = state.decisions.find(client_ip);
  if (it == state.decisions.end()) {
    return std::nullopt;
  }
  if (Clock::now() > it->second.expires_at) {
    state.decisions.erase(it);
    return std::nullopt;
  }
  return it->second.decision;
}

void maybe_store_decision(RuntimeState& state, const genwaf::EffectiveConfig& config, const RequestContext& req) {
  if (!config.behavior_enabled) {
    return;
  }

  auto it = req.headers.find("x-genbrain-decision");
  if (it == req.headers.end()) {
    return;
  }

  const int ttl_seconds = parse_ttl_seconds(config.decision_cache_ttl);
  std::lock_guard<std::mutex> lock(state.decision_mutex);
  if (state.decisions.size() >= static_cast<std::size_t>(std::max(1, config.max_decision_entries)) &&
      state.decisions.find(req.client_ip) == state.decisions.end()) {
    trim_map_to_limit(state.decisions, static_cast<std::size_t>(std::max(1, config.max_decision_entries - 1)));
  }
  DecisionEntry entry;
  entry.decision = it->second;
  entry.expires_at = Clock::now() + std::chrono::seconds(ttl_seconds);
  state.decisions[req.client_ip] = entry;
}

void record_observation(RuntimeState& state, const genwaf::EffectiveConfig& config, const RequestContext& req,
                        bool challenge_failure) {
  if (!config.cluster_sync_enabled || config.local_observation_path.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(state.observation_mutex);
  auto& entry = state.observations[req.client_ip];
  entry.fingerprint_id = req.fingerprint_id;
  entry.tls_fingerprint = req.tls_fingerprint;
  entry.tls_fingerprint_source = req.tls_fingerprint_source;
  entry.edge_bot_score = req.edge_bot_score;
  entry.http_fingerprint = req.http_fingerprint;
  entry.requests++;
  if (challenge_failure) {
    entry.challenge_failures++;
  }
  if (path_is_sensitive(config, req.path)) {
    entry.sensitive_hits++;
  }
  entry.last_seen = Clock::now();
  const std::size_t limit = static_cast<std::size_t>(std::max(128, config.rate_limit_max_tracked_ips / 2));
  if (state.observations.size() > limit) {
    trim_map_to_limit(state.observations, limit);
  }
}

void write_observations(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  if (!config.cluster_sync_enabled || config.local_observation_path.empty()) {
    return;
  }

  struct SnapshotEntry {
    std::string client_ip;
    ObservationEntry entry;
  };

  std::vector<SnapshotEntry> snapshot;
  {
    std::lock_guard<std::mutex> lock(state.observation_mutex);
    snapshot.reserve(state.observations.size());
    const auto now = Clock::now();
    for (auto it = state.observations.begin(); it != state.observations.end();) {
      if (now - it->second.last_seen > std::chrono::seconds(std::max(5, config.observation_window_seconds))) {
        it = state.observations.erase(it);
        continue;
      }
      snapshot.push_back(SnapshotEntry{it->first, it->second});
      ++it;
    }
  }

  std::sort(snapshot.begin(), snapshot.end(), [](const SnapshotEntry& left, const SnapshotEntry& right) {
    if (left.entry.requests == right.entry.requests) {
      return left.client_ip < right.client_ip;
    }
    return left.entry.requests > right.entry.requests;
  });
  if (snapshot.size() > 256) {
    snapshot.resize(256);
  }

  std::ostringstream out;
  out << "{\n";
  out << "  \"generated_at\": \"" << now_iso() << "\",\n";
  out << "  \"window_seconds\": " << std::max(5, config.observation_window_seconds) << ",\n";
  out << "  \"observations\": [\n";
  for (std::size_t i = 0; i < snapshot.size(); ++i) {
    const auto& item = snapshot[i];
    out << "    {"
        << "\"client_ip\":\"" << escape_json(item.client_ip) << "\","
        << "\"fingerprint_id\":\"" << escape_json(item.entry.fingerprint_id) << "\","
        << "\"tls_fingerprint\":\"" << escape_json(item.entry.tls_fingerprint) << "\","
        << "\"tls_fingerprint_source\":\"" << escape_json(item.entry.tls_fingerprint_source) << "\","
        << "\"edge_bot_score\":" << item.entry.edge_bot_score << ","
        << "\"http_fingerprint\":\"" << escape_json(item.entry.http_fingerprint) << "\","
        << "\"requests\":" << item.entry.requests << ","
        << "\"challenge_failures\":" << item.entry.challenge_failures << ","
        << "\"sensitive_hits\":" << item.entry.sensitive_hits
        << "}";
    if (i + 1 < snapshot.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "  ]\n";
  out << "}\n";

  const auto dir_pos = config.local_observation_path.find_last_of('/');
  if (dir_pos != std::string::npos) {
    const std::string dir = config.local_observation_path.substr(0, dir_pos);
    if (!dir.empty()) {
      ::mkdir(dir.c_str(), 0755);
    }
  }

  const std::string tmp_path = config.local_observation_path + ".tmp";
  {
    std::ofstream file(tmp_path, std::ios::trunc);
    if (!file) {
      return;
    }
    file << out.str();
  }
  std::rename(tmp_path.c_str(), config.local_observation_path.c_str());
}

void observation_flush_loop(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  const auto interval = std::chrono::milliseconds(std::max(250, config.observation_flush_interval_ms));
  while (g_running) {
    write_observations(state, config);
    std::this_thread::sleep_for(interval);
  }
}

std::string json_response(int status, const std::string& body, bool keep_alive, const std::vector<std::pair<std::string, std::string>>& extra_headers = {}) {
  std::ostringstream out;
  out << "HTTP/1.1 " << status << ' ';
  switch (status) {
    case 400:
      out << "Bad Request";
      break;
    case 200:
      out << "OK";
      break;
    case 403:
      out << "Forbidden";
      break;
    case 429:
      out << "Too Many Requests";
      break;
    case 501:
      out << "Not Implemented";
      break;
    case 502:
      out << "Bad Gateway";
      break;
    case 503:
      out << "Service Unavailable";
      break;
    default:
      out << "Error";
      break;
  }
  out << "\r\n";
  out << "Content-Type: application/json\r\n";
  out << "Content-Length: " << body.size() << "\r\n";
  out << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n";
  for (const auto& [key, value] : extra_headers) {
    out << key << ": " << value << "\r\n";
  }
  out << "\r\n";
  out << body;
  return out.str();
}

std::string html_response(int status, const std::string& body, bool keep_alive,
                          const std::vector<std::pair<std::string, std::string>>& extra_headers = {}) {
  std::ostringstream out;
  out << "HTTP/1.1 " << status << ' ';
  switch (status) {
    case 200:
      out << "OK";
      break;
    case 403:
      out << "Forbidden";
      break;
    default:
      out << "OK";
      break;
  }
  out << "\r\n";
  out << "Content-Type: text/html; charset=utf-8\r\n";
  out << "Content-Length: " << body.size() << "\r\n";
  out << "Cache-Control: no-store\r\n";
  out << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n";
  for (const auto& [key, value] : extra_headers) {
    out << key << ": " << value << "\r\n";
  }
  out << "\r\n";
  out << body;
  return out.str();
}

std::string now_iso() {
  std::time_t now = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&now, &tm);
  std::ostringstream out;
  out << std::put_time(&tm, "%FT%TZ");
  return out.str();
}

long long epoch_millis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string brand_logo_svg(const std::string& prefix) {
  const std::string surface = prefix + "-surface";
  const std::string stream = prefix + "-stream";
  const std::string core = prefix + "-core";
  const std::string aura = prefix + "-aura";
  std::ostringstream out;
  out << "<svg viewBox=\"0 0 512 512\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\" aria-hidden=\"true\">"
      << "<defs>"
      << "<linearGradient id=\"" << surface << "\" x1=\"76\" y1=\"58\" x2=\"438\" y2=\"454\" gradientUnits=\"userSpaceOnUse\">"
      << "<stop stop-color=\"#091426\"/><stop offset=\"1\" stop-color=\"#183556\"/></linearGradient>"
      << "<linearGradient id=\"" << stream << "\" x1=\"112\" y1=\"146\" x2=\"402\" y2=\"346\" gradientUnits=\"userSpaceOnUse\">"
      << "<stop stop-color=\"#1FD5A4\"/><stop offset=\"1\" stop-color=\"#4B7CFF\"/></linearGradient>"
      << "<linearGradient id=\"" << core << "\" x1=\"218\" y1=\"176\" x2=\"302\" y2=\"326\" gradientUnits=\"userSpaceOnUse\">"
      << "<stop stop-color=\"#F7FCFF\"/><stop offset=\"1\" stop-color=\"#B9DCFF\"/></linearGradient>"
      << "<radialGradient id=\"" << aura
      << "\" cx=\"0\" cy=\"0\" r=\"1\" gradientUnits=\"userSpaceOnUse\" gradientTransform=\"translate(256 256) rotate(90) scale(170)\">"
      << "<stop stop-color=\"#6BC7FF\" stop-opacity=\"0.28\"/><stop offset=\"0.7\" stop-color=\"#3B82F6\" stop-opacity=\"0.08\"/>"
      << "<stop offset=\"1\" stop-color=\"#3B82F6\" stop-opacity=\"0\"/></radialGradient></defs>"
      << "<rect width=\"512\" height=\"512\" rx=\"124\" fill=\"#F7FBFF\"/>"
      << "<rect x=\"42\" y=\"42\" width=\"428\" height=\"428\" rx=\"110\" fill=\"url(#" << surface << ")\"/>"
      << "<circle cx=\"256\" cy=\"256\" r=\"162\" fill=\"url(#" << aura << ")\"/>"
      << "<circle cx=\"256\" cy=\"256\" r=\"112\" stroke=\"url(#" << stream << ")\" stroke-width=\"36\"/>"
      << "<circle cx=\"256\" cy=\"256\" r=\"78\" fill=\"#10233A\" fill-opacity=\"0.96\"/>"
      << "<rect x=\"110\" y=\"149\" width=\"150\" height=\"28\" rx=\"14\" fill=\"url(#" << stream << ")\"/>"
      << "<rect x=\"94\" y=\"242\" width=\"166\" height=\"28\" rx=\"14\" fill=\"url(#" << stream << ")\" fill-opacity=\"0.94\"/>"
      << "<rect x=\"110\" y=\"335\" width=\"150\" height=\"28\" rx=\"14\" fill=\"url(#" << stream << ")\" fill-opacity=\"0.8\"/>"
      << "<rect x=\"292\" y=\"242\" width=\"126\" height=\"28\" rx=\"14\" fill=\"url(#" << stream << ")\"/>"
      << "<rect x=\"214\" y=\"176\" width=\"84\" height=\"160\" rx=\"30\" fill=\"url(#" << core << ")\"/>"
      << "<rect x=\"240\" y=\"206\" width=\"32\" height=\"100\" rx=\"16\" fill=\"#10233A\"/>"
      << "<circle cx=\"158\" cy=\"110\" r=\"12\" fill=\"#D9EDFF\" fill-opacity=\"0.9\"/>"
      << "<circle cx=\"374\" cy=\"126\" r=\"10\" fill=\"#1FD5A4\" fill-opacity=\"0.95\"/>"
      << "<circle cx=\"356\" cy=\"382\" r=\"14\" fill=\"#D9EDFF\" fill-opacity=\"0.78\"/>"
      << "</svg>";
  return out.str();
}

std::string make_challenge_page(const genwaf::EffectiveConfig& config, const RuntimeState& state, const RequestContext& req) {
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
  const long long expires_at = now + 120;
  const int difficulty = config.pow_enabled ? std::max(1, config.challenge_difficulty) : 1;
  const std::string seed = hex_u64(fnv1a64(req.client_ip + "|" + req.path + "|" + std::to_string(now) + "|" + now_iso()));
  const std::string sig = challenge_signature(state, req, req.path, seed, expires_at, difficulty);
  const std::string title = escape_html(config.name.empty() ? "GEN WAF" : config.name);
  const std::string path = escape_html(req.path);

  std::ostringstream out;
  out << "<!doctype html><html><head><meta charset=\"utf-8\">"
      << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      << "<title>" << title << " - Đang xác minh</title>"
      << "<style>"
         ":root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#15304a;background:#f6fafc;}"
         "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;text-align:center;background:"
         "radial-gradient(circle at top left,rgba(45,109,246,.12),transparent 22%),"
         "radial-gradient(circle at top right,rgba(31,191,143,.12),transparent 24%),"
         "linear-gradient(180deg,#f8fbff,#eef4f7);}"
         ".card{width:min(94vw,620px);background:rgba(255,255,255,.96);border:1px solid rgba(21,48,74,.08);border-radius:34px;"
         "padding:34px;box-shadow:0 24px 64px rgba(15,23,42,.1)}"
         ".brand{display:flex;align-items:center;justify-content:center;gap:16px;margin-bottom:20px;text-align:left}"
         ".logo{width:64px;height:64px;flex:0 0 64px}"
         ".logo svg{display:block;width:100%;height:100%}"
         ".brand-copy{display:grid;gap:4px}"
         ".brand-copy strong{font-size:.98rem;letter-spacing:.18em;text-transform:uppercase;color:#10233a}"
         ".brand-copy span{font-size:.88rem;color:#5f7387}"
         ".pill{display:inline-flex;padding:7px 11px;border-radius:999px;background:#e9f3ff;color:#2456c6;font-size:.78rem;font-weight:700;margin-bottom:10px}"
         "h1{margin:0 0 10px;font-size:clamp(2rem,4vw,3rem);line-height:1.02;letter-spacing:-.04em}"
         "p{margin:0 auto;color:#60758a;line-height:1.65;max-width:34rem}"
         ".route{margin-top:16px;color:#3e5870;font-size:.95rem}"
         ".route strong{color:#15304a}"
         ".panel{margin-top:20px;padding:20px;border-radius:26px;background:linear-gradient(180deg,#132239,#182e49);color:#edf4fb;text-align:left}"
         ".panel p{color:#bcd0e1}"
         ".progress{margin-top:14px;height:10px;border-radius:999px;background:rgba(255,255,255,.14);overflow:hidden}"
         ".bar{height:100%;width:0;background:linear-gradient(90deg,#34d399,#60a5fa);transition:width .14s ease}"
         ".status{margin-top:12px;font-size:.95rem;color:#edf4fb}"
         ".sub{margin-top:18px;font-size:.88rem;color:#6d8195}"
         ".footer{margin-top:18px;font-size:.82rem;color:#7d8fa2;letter-spacing:.04em;text-transform:uppercase}"
      << "</style></head><body>"
      << "<main class=\"card\">"
      << "<div class=\"brand\"><div class=\"logo\">" << brand_logo_svg("challenge-logo") << "</div>"
      << "<div class=\"brand-copy\"><strong>GEN WAF</strong><span>Self-hosted protective reverse proxy</span></div></div>"
      << "<div><div class=\"pill\">JavaScript Challenge</div><h1>Đang xác minh truy cập</h1>"
      << "<p>Hệ thống đang xác minh trình duyệt thật để giữ origin ổn định và giảm lưu lượng bot tự động.</p></div>"
      << "<div class=\"route\">Đường dẫn: <strong>" << path << "</strong> · Chế độ: <strong>"
      << escape_html(config.js_challenge ? "JS + PoW" : "PoW") << "</strong></div>"
      << "<section class=\"panel\">"
      << "<p>Challenge này được tính toán ngay trong trình duyệt và không gọi CAPTCHA bên thứ ba.</p>"
      << "<div class=\"progress\"><div class=\"bar\" id=\"bar\"></div></div>"
      << "<div class=\"status\" id=\"status\">Đang bắt đầu xác minh…</div>"
      << "</section>"
      << "<div class=\"sub\">Bạn không cần thao tác gì thêm ở bước này.</div>"
      << "<div class=\"footer\">Protected by GEN WAF</div>"
      << "</main>"
      << "<script>"
         "const seed=" << "\"" << seed << "\";"
         "const sig=" << "\"" << sig << "\";"
         "const exp=" << expires_at << ";"
         "const difficulty=" << difficulty << ";"
         "const targetPath=" << "\"" << escape_json(req.path) << "\";"
         "const bar=document.getElementById('bar');"
         "function fnv1a64(str){let h=0xcbf29ce484222325n;for(let i=0;i<str.length;i++){h^=BigInt(str.charCodeAt(i));h=(h*0x100000001b3n)&0xffffffffffffffffn;}return h.toString(16).padStart(16,'0');}"
         "function meets(hex,d){for(let i=0;i<d;i++){if(hex[i]!=='0')return false;}return true;}"
         "async function solve(){let nonce=0;const status=document.getElementById('status');const quantum=2048;while(true){for(let i=0;i<quantum;i++,nonce++){const hex=fnv1a64(seed+':'+nonce);if(meets(hex,difficulty)){bar.style.width='100%';status.textContent='Đã xác minh, đang mở lại trang…';const body='kind=challenge&seed='+encodeURIComponent(seed)+'&sig='+encodeURIComponent(sig)+'&exp='+encodeURIComponent(exp)+'&nonce='+encodeURIComponent(nonce)+'&difficulty='+encodeURIComponent(difficulty)+'&path='+encodeURIComponent(targetPath);const res=await fetch('/__genwaf/challenge/verify',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});if(res.ok){window.location.replace(targetPath||'/');return;}status.textContent='Xác minh thất bại, đang thử lại…';nonce=0;bar.style.width='0%';break;}}bar.style.width=((nonce%(quantum*8))/(quantum*8)*100).toFixed(1)+'%';status.textContent='Đang xác minh…';await new Promise(r=>setTimeout(r,0));}}"
         "solve();"
      << "</script></body></html>";
  return out.str();
}

std::string make_captcha_page(const genwaf::EffectiveConfig& config, const RuntimeState& state, const RequestContext& req) {
  const long long issued_at_ms = epoch_millis();
  const long long expires_at_ms = issued_at_ms + 120000;
  const std::string sig = captcha_signature(state, req, req.path, issued_at_ms, expires_at_ms);
  const std::string title = escape_html(config.name.empty() ? "GEN WAF" : config.name);
  const std::string path = escape_html(req.path);

  std::ostringstream out;
  out << "<!doctype html><html><head><meta charset=\"utf-8\">"
      << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      << "<title>" << title << " - Xác minh nhanh</title>"
      << "<style>"
         ":root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#15304a;background:#f6fafc;}"
         "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;text-align:center;background:"
         "radial-gradient(circle at top left,rgba(31,191,143,.14),transparent 24%),"
         "radial-gradient(circle at top right,rgba(45,109,246,.12),transparent 24%),"
         "linear-gradient(180deg,#f8fbff,#eef4f7);}"
         ".card{width:min(94vw,620px);background:rgba(255,255,255,.96);border:1px solid rgba(21,48,74,.08);border-radius:34px;"
         "padding:34px;box-shadow:0 24px 64px rgba(15,23,42,.1)}"
         ".brand{display:flex;align-items:center;justify-content:center;gap:16px;margin-bottom:20px;text-align:left}"
         ".logo{width:64px;height:64px;flex:0 0 64px}"
         ".logo svg{display:block;width:100%;height:100%}"
         ".brand-copy{display:grid;gap:4px}"
         ".brand-copy strong{font-size:.98rem;letter-spacing:.18em;text-transform:uppercase;color:#10233a}"
         ".brand-copy span{font-size:.88rem;color:#5f7387}"
         ".pill{display:inline-flex;padding:7px 11px;border-radius:999px;background:#e9f8f1;color:#16825e;font-size:.78rem;font-weight:700;margin-bottom:10px}"
         "h1{margin:0 0 10px;font-size:clamp(2rem,4vw,3rem);line-height:1.02;letter-spacing:-.04em}"
         "p{margin:0 auto;color:#60758a;line-height:1.65;max-width:30rem}"
         ".route{margin-top:16px;color:#3e5870;font-size:.95rem}.route strong{color:#15304a}"
         ".hold{position:relative;display:flex;align-items:center;justify-content:center;width:100%;height:72px;border:none;border-radius:999px;"
         "margin-top:20px;font-size:1rem;font-weight:700;color:#fff;background:linear-gradient(90deg,#21c295,#2d6df6);cursor:pointer;overflow:hidden;"
         "box-shadow:0 14px 26px rgba(45,109,246,.16);user-select:none;-webkit-user-select:none;touch-action:none}"
         ".fill{position:absolute;inset:0 auto 0 0;width:0;background:rgba(255,255,255,.18)}"
         ".label{position:relative;z-index:1}.note{margin-top:14px;color:#6d8195;font-size:.92rem;min-height:1.4em}"
         ".ok{color:#16775b;font-weight:700}.err{color:#b42318;font-weight:700}"
         ".footer{margin-top:18px;font-size:.82rem;color:#7d8fa2;letter-spacing:.04em;text-transform:uppercase}"
      << "</style></head><body>"
      << "<main class=\"card\">"
      << "<div class=\"brand\"><div class=\"logo\">" << brand_logo_svg("captcha-logo") << "</div>"
      << "<div class=\"brand-copy\"><strong>GEN WAF</strong><span>Interactive verification checkpoint</span></div></div>"
      << "<div><div class=\"pill\">Hold-to-Continue CAPTCHA</div><h1>Xác minh nhanh</h1><p>Nhấn và giữ nút bên dưới để chứng minh đây là thao tác thật.</p></div>"
      << "<div class=\"route\">Đường dẫn: <strong>" << path << "</strong></div>"
      << "<button id=\"hold\" class=\"hold\" aria-label=\"Nhấn và giữ để tiếp tục\"><span class=\"fill\" id=\"fill\"></span><span class=\"label\" id=\"label\">Nhấn và giữ để tiếp tục</span></button>"
      << "<div class=\"note\" id=\"note\">Giữ khoảng 1,2 giây để hoàn tất xác minh.</div>"
      << "<div class=\"footer\">Protected by GEN WAF</div>"
      << "</main>"
      << "<script>"
         "const issuedAt=" << issued_at_ms << ";"
         "const expiresAt=" << expires_at_ms << ";"
         "const sig=" << "\"" << sig << "\";"
         "const targetPath=" << "\"" << escape_json(req.path) << "\";"
         "const holdMs=1200;"
         "let frame=0,start=0,active=false;"
         "const hold=document.getElementById('hold'),fill=document.getElementById('fill'),label=document.getElementById('label'),note=document.getElementById('note');"
         "function resetState(msg){if(frame)cancelAnimationFrame(frame);frame=0;start=0;active=false;fill.style.width='0%';label.textContent='Nhấn và giữ để tiếp tục';if(msg)note.textContent=msg;}"
         "async function verify(){label.textContent='Đang xác minh…';const body='kind=captcha&issued_at_ms='+encodeURIComponent(issuedAt)+'&exp_ms='+encodeURIComponent(expiresAt)+'&sig='+encodeURIComponent(sig)+'&path='+encodeURIComponent(targetPath);const res=await fetch('/__genwaf/challenge/verify',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});if(res.ok){note.innerHTML='<span class=\"ok\">Đã xác minh, đang mở lại trang…</span>';window.location.replace(targetPath||'/');return;}note.innerHTML='<span class=\"err\">Xác minh thất bại, vui lòng thử lại.</span>';resetState();}"
         "function tick(){if(!active)return;const elapsed=Date.now()-start;const pct=Math.min(100,(elapsed/holdMs)*100);fill.style.width=pct+'%';if(elapsed>=holdMs){active=false;frame=0;verify();return;}frame=requestAnimationFrame(tick);}"
         "function begin(){if(active)return;active=true;start=Date.now();label.textContent='Đang giữ…';note.textContent='Giữ nguyên cho đến khi thanh tiến trình đầy.';frame=requestAnimationFrame(tick);}"
         "function stop(){if(!active)return;const elapsed=Date.now()-start;active=false;if(frame)cancelAnimationFrame(frame);frame=0;if(elapsed<holdMs){resetState('Bạn cần giữ thêm một chút để hoàn tất.');}}"
         "hold.addEventListener('pointerdown',begin);window.addEventListener('pointerup',stop);window.addEventListener('pointercancel',stop);window.addEventListener('pointerleave',stop);"
      << "</script></body></html>";
  return out.str();
}

void trim_map_to_limit(std::unordered_map<std::string, CacheEntry>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

void trim_map_to_limit(std::unordered_map<std::string, DecisionEntry>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

void trim_map_to_limit(std::unordered_map<std::string, UsedChallengeTokenEntry>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

void trim_map_to_limit(std::unordered_map<std::string, TokenBucket>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

void trim_map_to_limit(std::unordered_map<std::string, ObservationEntry>& entries, std::size_t limit) {
  while (entries.size() > limit && !entries.empty()) {
    entries.erase(entries.begin());
  }
}

std::string make_status_body(const genwaf::EffectiveConfig& config, RuntimeState& state) {
  std::size_t healthy_backends = 0;
  std::size_t unhealthy_backends = 0;
  std::size_t shared_decisions = 0;
  std::size_t shared_rate_limited_clients = 0;
  std::size_t used_challenge_tokens = 0;
  std::size_t pressured_clients = 0;
  std::size_t hot_fingerprints = 0;
  {
    std::lock_guard<std::mutex> lock(state.backend_mutex);
    for (const auto& [_, status] : state.backend_states) {
      if (status.healthy) {
        healthy_backends++;
      } else {
        unhealthy_backends++;
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
    shared_decisions = state.cluster_decisions.size();
  }
  {
    std::lock_guard<std::mutex> lock(state.challenge_token_mutex);
    used_challenge_tokens = state.used_challenge_tokens.size();
  }
  {
    std::lock_guard<std::mutex> lock(state.shared_rate_limit_mutex);
    shared_rate_limited_clients = state.shared_rate_limits.size();
  }
  {
    std::lock_guard<std::mutex> lock(state.local_pressure_mutex);
    pressured_clients = state.local_pressure.size();
  }
  {
    std::lock_guard<std::mutex> lock(state.fingerprint_mutex);
    hot_fingerprints = state.fingerprint_reputation.size();
  }

  std::ostringstream out;
  out << "{"
      << "\"name\":\"" << config.name << "\","
      << "\"mode\":\"" << config.mode << "\","
      << "\"worker_threads\":" << config.worker_threads << ","
      << "\"active_connections\":" << state.active_connections.load() << ","
      << "\"max_active_connections\":" << config.max_active_connections << ","
      << "\"max_keepalive_requests\":" << config.max_keepalive_requests << ","
      << "\"total_requests\":" << state.metrics.total_requests.load() << ","
      << "\"blocked_requests\":" << state.metrics.blocked_requests.load() << ","
      << "\"challenged_requests\":" << state.metrics.challenged_requests.load() << ","
      << "\"rate_limited_requests\":" << state.metrics.rate_limited_requests.load() << ","
      << "\"shed_connections\":" << state.metrics.shed_connections.load() << ","
      << "\"cache_hits\":" << state.metrics.cache_hits.load() << ","
      << "\"cache_misses\":" << state.metrics.cache_misses.load() << ","
      << "\"replay_protection\":" << (config.replay_protection ? "true" : "false") << ","
      << "\"used_challenge_tokens\":" << used_challenge_tokens << ","
      << "\"pressured_clients\":" << pressured_clients << ","
      << "\"hot_fingerprints\":" << hot_fingerprints << ","
      << "\"shared_decisions\":" << shared_decisions << ","
      << "\"shared_rate_limit_clients\":" << shared_rate_limited_clients << ","
      << "\"healthy_backends\":" << healthy_backends << ","
      << "\"unhealthy_backends\":" << unhealthy_backends << ","
      << "\"generated_at\":\"" << now_iso() << "\""
      << "}";
  return out.str();
}

std::optional<std::string> get_cached_body(RuntimeState& state, const std::string& key) {
  std::lock_guard<std::mutex> lock(state.cache_mutex);
  const auto it = state.cache.find(key);
  if (it == state.cache.end() || Clock::now() > it->second.expires_at) {
    return std::nullopt;
  }
  return it->second.body;
}

void store_cached_body(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& key,
                       const std::string& body, bool aggressive) {
  std::lock_guard<std::mutex> lock(state.cache_mutex);
  if (state.cache.size() >= static_cast<std::size_t>(std::max(1, config.max_response_cache_entries)) &&
      state.cache.find(key) == state.cache.end()) {
    trim_map_to_limit(state.cache, static_cast<std::size_t>(std::max(1, config.max_response_cache_entries - 1)));
  }
  const auto ttl = aggressive ? std::chrono::seconds(120) : std::chrono::seconds(30);
  CacheEntry entry;
  entry.body = body;
  entry.expires_at = Clock::now() + ttl;
  state.cache[key] = entry;
}

std::string build_application_body(const RequestContext& req) {
  std::ostringstream out;
  out << "{"
      << "\"status\":\"ok\","
      << "\"path\":\"" << req.path << "\","
      << "\"host\":\"" << req.host << "\","
      << "\"method\":\"" << req.method << "\","
      << "\"served_at\":\"" << now_iso() << "\""
      << "}";
  return out.str();
}

std::string peer_ip(sockaddr_in addr) {
  char buffer[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer));
  return buffer;
}

void log_if_enabled(RuntimeState& state, const genwaf::EffectiveConfig& config, const std::string& message) {
  if (!config.logs_enabled) {
    return;
  }
  std::lock_guard<std::mutex> lock(state.log_mutex);
  const auto now = Clock::now();
  if (now - state.log_window_start >= std::chrono::seconds(5)) {
    if (state.suppressed_logs_in_window > 0) {
      std::cout << "[gendp] suppressed " << state.suppressed_logs_in_window << " repetitive logs in last window"
                << std::endl;
    }
    state.log_window_start = now;
    state.emitted_logs_in_window = 0;
    state.suppressed_logs_in_window = 0;
  }
  if (state.emitted_logs_in_window < 12) {
    std::cout << "[gendp] " << message << std::endl;
    state.emitted_logs_in_window++;
    return;
  }
  state.suppressed_logs_in_window++;
}

void maybe_compact_runtime_state(RuntimeState& state, const genwaf::EffectiveConfig& config) {
  {
    std::lock_guard<std::mutex> lock(state.bucket_mutex);
    const auto now = Clock::now();
    for (auto it = state.buckets.begin(); it != state.buckets.end();) {
      if (now - it->second.last_seen > std::chrono::seconds(90)) {
        it = state.buckets.erase(it);
        continue;
      }
      ++it;
    }
    trim_map_to_limit(state.buckets, static_cast<std::size_t>(std::max(1, config.rate_limit_max_tracked_ips)));
  }
  {
    std::lock_guard<std::mutex> lock(state.decision_mutex);
    const auto now = Clock::now();
    for (auto it = state.decisions.begin(); it != state.decisions.end();) {
      if (now > it->second.expires_at) {
        it = state.decisions.erase(it);
        continue;
      }
      ++it;
    }
    trim_map_to_limit(state.decisions, static_cast<std::size_t>(std::max(1, config.max_decision_entries)));
  }
  {
    std::lock_guard<std::mutex> lock(state.challenge_token_mutex);
    const auto now = Clock::now();
    for (auto it = state.used_challenge_tokens.begin(); it != state.used_challenge_tokens.end();) {
      if (now > it->second.expires_at) {
        it = state.used_challenge_tokens.erase(it);
        continue;
      }
      ++it;
    }
    trim_map_to_limit(state.used_challenge_tokens,
                      static_cast<std::size_t>(std::max(64, config.challenge_token_cache_entries)));
  }
  {
    std::lock_guard<std::mutex> lock(state.cache_mutex);
    const auto now = Clock::now();
    for (auto it = state.cache.begin(); it != state.cache.end();) {
      if (now > it->second.expires_at) {
        it = state.cache.erase(it);
        continue;
      }
      ++it;
    }
    trim_map_to_limit(state.cache, static_cast<std::size_t>(std::max(1, config.max_response_cache_entries)));
  }
  {
    std::lock_guard<std::mutex> lock(state.cluster_decision_mutex);
    const auto now = Clock::now();
    for (auto it = state.cluster_decisions.begin(); it != state.cluster_decisions.end();) {
      if (now > it->second.expires_at) {
        it = state.cluster_decisions.erase(it);
        continue;
      }
      ++it;
    }
  }
  {
    std::lock_guard<std::mutex> lock(state.observation_mutex);
    const auto now = Clock::now();
    for (auto it = state.observations.begin(); it != state.observations.end();) {
      if (now - it->second.last_seen > std::chrono::seconds(std::max(5, config.observation_window_seconds))) {
        it = state.observations.erase(it);
        continue;
      }
      ++it;
    }
    const std::size_t limit = static_cast<std::size_t>(std::max(128, config.rate_limit_max_tracked_ips / 2));
    trim_map_to_limit(state.observations, limit);
  }
  {
    std::lock_guard<std::mutex> lock(state.local_pressure_mutex);
    const auto now = Clock::now();
    for (auto it = state.local_pressure.begin(); it != state.local_pressure.end();) {
      if (now > it->second.expires_at) {
        it = state.local_pressure.erase(it);
        continue;
      }
      ++it;
    }
    trim_map_to_limit(state.local_pressure,
                      static_cast<std::size_t>(std::max(128, config.rate_limit_max_tracked_ips / 4)));
  }
  {
    std::lock_guard<std::mutex> lock(state.fingerprint_mutex);
    const auto now = Clock::now();
    for (auto it = state.fingerprint_reputation.begin(); it != state.fingerprint_reputation.end();) {
      if (now > it->second.expires_at) {
        it = state.fingerprint_reputation.erase(it);
        continue;
      }
      ++it;
    }
    trim_map_to_limit(state.fingerprint_reputation,
                      static_cast<std::size_t>(std::max(128, config.rate_limit_max_tracked_ips / 4)));
  }
}

std::string handle_challenge_verify(const genwaf::EffectiveConfig& config, RuntimeState& state, const RequestContext& req,
                                    bool keep_alive, bool* ok) {
  const auto fields = parse_form_body(req.body);
  const auto kind_it = fields.find("kind");
  const auto sig_it = fields.find("sig");
  const auto path_it = fields.find("path");
  if (kind_it == fields.end() || sig_it == fields.end() || path_it == fields.end()) {
    *ok = false;
    return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"missing_fields\"}", keep_alive);
  }

  try {
    if (kind_it->second == "captcha") {
      const auto issued_it = fields.find("issued_at_ms");
      const auto exp_it = fields.find("exp_ms");
      if (issued_it == fields.end() || exp_it == fields.end()) {
        *ok = false;
        return json_response(403, "{\"status\":\"captcha_failed\",\"reason\":\"missing_fields\"}", keep_alive);
      }
      const long long issued_at_ms = std::stoll(issued_it->second);
      const long long expires_at_ms = std::stoll(exp_it->second);
      const long long now_ms = epoch_millis();
      if (expires_at_ms <= now_ms) {
        *ok = false;
        return json_response(403, "{\"status\":\"captcha_failed\",\"reason\":\"expired\"}", keep_alive);
      }
      if (now_ms - issued_at_ms < 1200) {
        *ok = false;
        return json_response(403, "{\"status\":\"captcha_failed\",\"reason\":\"hold_too_short\"}", keep_alive);
      }
      const std::string expected_sig = captcha_signature(state, req, path_it->second, issued_at_ms, expires_at_ms);
      if (!timing_safe_equal(expected_sig, sig_it->second)) {
        *ok = false;
        return json_response(403, "{\"status\":\"captcha_failed\",\"reason\":\"bad_signature\"}", keep_alive);
      }
      const auto remaining_ms = std::max<long long>(1, expires_at_ms - now_ms);
      if (!consume_challenge_token(state, config, challenge_token_key("captcha", sig_it->second),
                                   Clock::now() + std::chrono::milliseconds(remaining_ms))) {
        *ok = false;
        return json_response(403, "{\"status\":\"captcha_failed\",\"reason\":\"replayed_token\"}", keep_alive);
      }
    } else {
      const auto seed_it = fields.find("seed");
      const auto exp_it = fields.find("exp");
      const auto nonce_it = fields.find("nonce");
      const auto diff_it = fields.find("difficulty");
      if (seed_it == fields.end() || exp_it == fields.end() || nonce_it == fields.end() || diff_it == fields.end()) {
        *ok = false;
        return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"missing_fields\"}", keep_alive);
      }
      const long long expires_at = std::stoll(exp_it->second);
      const int difficulty = std::stoi(diff_it->second);
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
      if (expires_at <= now) {
        *ok = false;
        return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"expired\"}", keep_alive);
      }
      if (difficulty < 0 || difficulty > 8) {
        *ok = false;
        return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"invalid_difficulty\"}", keep_alive);
      }
      const std::string expected_sig =
          challenge_signature(state, req, path_it->second, seed_it->second, expires_at, difficulty);
      if (!timing_safe_equal(expected_sig, sig_it->second)) {
        *ok = false;
        return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"bad_signature\"}", keep_alive);
      }
      const uint64_t proof = fnv1a64(seed_it->second + ":" + nonce_it->second);
      if (!has_leading_zero_nibbles(proof, difficulty)) {
        *ok = false;
        return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"bad_proof\"}", keep_alive);
      }
      const auto remaining_seconds = std::max<long long>(1, expires_at - now);
      if (!consume_challenge_token(state, config, challenge_token_key("challenge", sig_it->second),
                                   Clock::now() + std::chrono::seconds(remaining_seconds))) {
        *ok = false;
        return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"replayed_token\"}", keep_alive);
      }
    }
    *ok = true;
    return json_response(200, "{\"status\":\"ok\"}", keep_alive, {{"Set-Cookie", issue_pass_cookie(config, state, req)}});
  } catch (...) {
    *ok = false;
    return json_response(403, "{\"status\":\"challenge_failed\",\"reason\":\"parse_error\"}", keep_alive);
  }
}

bool try_acquire_connection_slot(RuntimeState& state, int max_active_connections) {
  int current = state.active_connections.load();
  while (current < max_active_connections) {
    if (state.active_connections.compare_exchange_weak(current, current + 1)) {
      return true;
    }
  }
  return false;
}

struct ConnectionSlotGuard {
  RuntimeState& state;

  ~ConnectionSlotGuard() {
    state.active_connections--;
  }
};

bool set_nonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::optional<ConnectionTask> pop_connection_task(ConnectionQueue& queue) {
  std::unique_lock<std::mutex> lock(queue.mutex);
  queue.cv.wait(lock, [&] { return queue.stopping || !queue.tasks.empty(); });
  if (queue.tasks.empty()) {
    return std::nullopt;
  }
  ConnectionTask task = queue.tasks.front();
  queue.tasks.pop();
  return task;
}

void push_connection_task(ConnectionQueue& queue, ConnectionTask task) {
  {
    std::lock_guard<std::mutex> lock(queue.mutex);
    queue.tasks.push(task);
  }
  queue.cv.notify_one();
}

void stop_connection_queue(ConnectionQueue& queue) {
  {
    std::lock_guard<std::mutex> lock(queue.mutex);
    queue.stopping = true;
  }
  queue.cv.notify_all();
}

void handle_connection(int client_fd, sockaddr_in client_addr, genwaf::EffectiveConfig config, RuntimeState& state) {
  ConnectionSlotGuard connection_guard{state};
  const std::string peer = peer_ip(client_addr);
  int handled_requests = 0;
  timeval client_timeout{};
  client_timeout.tv_sec = config.header_read_timeout_ms / 1000;
  client_timeout.tv_usec = (config.header_read_timeout_ms % 1000) * 1000;
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
  while (true) {
    const auto raw_request = read_http_request(client_fd, config.max_request_bytes);
    if (!raw_request.has_value()) {
      break;
    }

    auto request = parse_request(raw_request.value(), config, peer);
    if (!request.has_value()) {
      const std::string response =
          json_response(400, "{\"status\":\"bad_request\",\"reason\":\"http_parser_rejected_request\"}", false);
      send_all(client_fd, response);
      break;
    }
    populate_request_fingerprint(state, config, *request);
    handled_requests++;
    const bool keep_alive = request->keep_alive && handled_requests < std::max(1, config.max_keepalive_requests);

    state.metrics.total_requests++;
    if ((state.metrics.total_requests.load() & 255ULL) == 0) {
      maybe_compact_runtime_state(state, config);
    }
    refresh_cluster_decisions(state, config);
    refresh_shared_rate_limits(state, config);
    maybe_store_decision(state, config, *request);

    std::vector<std::pair<std::string, std::string>> headers;
    const std::string cache_key = request->host + "|" + request->path;

    if (request->path == "/healthz") {
      const std::string body = "{\"status\":\"ok\"}";
      const std::string response = json_response(200, body, keep_alive);
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    if (request->path == "/__genwaf/status") {
      const std::string body = make_status_body(config, state);
      const std::string response = json_response(200, body, keep_alive);
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    if (!edge_verified(config, *request)) {
      state.metrics.blocked_requests++;
      adjust_fingerprint_reputation(state, config, *request, 6, false);
      const std::string body = "{\"status\":\"blocked\",\"reason\":\"edge verification failed\"}";
      const std::string response = json_response(403, body, keep_alive);
      send_all(client_fd, response);
      log_if_enabled(state, config, "blocked request from " + peer + " because edge verification failed");
      if (!keep_alive) {
        break;
      }
      continue;
    }

    if (request->path == "/__genwaf/challenge/verify" && request->method == "POST") {
      bool verified = false;
      const std::string response = handle_challenge_verify(config, state, *request, keep_alive, &verified);
      if (!verified) {
        state.metrics.blocked_requests++;
        record_observation(state, config, *request, true);
        adjust_local_pressure(state, config, request->client_ip, 4);
        adjust_fingerprint_reputation(state, config, *request, 10, true);
      } else {
        record_observation(state, config, *request, false);
        clear_local_pressure(state, request->client_ip);
        adjust_fingerprint_reputation(state, config, *request, -8, false);
      }
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    record_observation(state, config, *request, false);
    adjust_fingerprint_reputation(state, config, *request, path_is_sensitive(config, request->path) ? 1 : 0, false);

    const auto decision = cached_decision(state, config, request->client_ip);
    if (decision.has_value() && (decision.value() == "temporary_ban" || decision.value() == "drop_at_xdp")) {
      state.metrics.blocked_requests++;
      adjust_fingerprint_reputation(state, config, *request, 8, false);
      const std::string body = "{\"status\":\"blocked\",\"reason\":\"cached behavior decision\"}";
      const std::string response = json_response(403, body, keep_alive);
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    const auto shared_decision = cluster_decision_for_request(state, *request);
    if (shared_decision.has_value() &&
        (shared_decision->action == "temporary_ban" || shared_decision->action == "drop_at_xdp")) {
      state.metrics.blocked_requests++;
      adjust_fingerprint_reputation(state, config, *request, 10, false);
      const std::string body = "{\"status\":\"blocked\",\"reason\":\"shared cluster decision\"}";
      const std::string response = json_response(403, body, keep_alive,
                                                 {{"X-GENWAF-Cluster-Decision", shared_decision->action}});
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    if (!allow_by_rate_limit(state, config, request->client_ip)) {
      state.metrics.rate_limited_requests++;
      adjust_local_pressure(state, config, request->client_ip, path_is_sensitive(config, request->path) ? 3 : 2);
      adjust_fingerprint_reputation(state, config, *request, path_is_sensitive(config, request->path) ? 6 : 4, false);
      const std::string body = "{\"status\":\"rate_limited\",\"reason\":\"token bucket exceeded\"}";
      const std::string response = json_response(429, body, keep_alive);
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    const auto ua = request->headers.find("user-agent");
    const auto cookie = request->headers.find("cookie");
    const genwaf::WAFResult waf = genwaf::evaluate_waf(
        config,
        genwaf::WAFInput{
            .path = request->path,
            .user_agent = ua == request->headers.end() ? "" : ua->second,
            .has_cookie = cookie != request->headers.end(),
            .sensitive_path = path_is_sensitive(config, request->path),
        });
    if (waf.should_block) {
      state.metrics.blocked_requests++;
      adjust_local_pressure(state, config, request->client_ip, 4);
      adjust_fingerprint_reputation(state, config, *request, 9, false);
      const std::string body = "{\"status\":\"blocked\",\"reason\":\"waf anomaly threshold reached\"}";
      const std::string response = json_response(403, body, keep_alive, {{"X-GENWAF-WAF", "block"}});
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }
    if (waf.score > 0) {
      adjust_local_pressure(state, config, request->client_ip, std::min(3, waf.score));
      adjust_fingerprint_reputation(state, config, *request, std::min(6, waf.score + 1), false);
      headers.push_back({"X-GENWAF-WAF", config.waf_mode == "detect_only" ? "detect" : "score"});
    }

    const bool has_pass_cookie = has_valid_pass_cookie(config, state, *request);
    const bool forced_soft_challenge = shared_decision.has_value() && shared_decision->action == "soft_challenge";
    const bool forced_pow_challenge = shared_decision.has_value() && shared_decision->action == "pow_challenge";
    const std::string local_action = local_progressive_action(state, request->client_ip);
    const std::string fingerprint_action = fingerprint_progressive_action(state, *request);
    const std::string effective_local_action = stronger_progressive_action(local_action, fingerprint_action);
    if (effective_local_action == "temporary_ban") {
      state.metrics.blocked_requests++;
      const std::string body = "{\"status\":\"blocked\",\"reason\":\"local progressive defense\"}";
      const std::string response = json_response(403, body, keep_alive, {{"X-GENWAF-Local-Decision", effective_local_action}});
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }
    const bool should_challenge = !has_pass_cookie && config.bot_defense_enabled &&
                                  (forced_soft_challenge || forced_pow_challenge || effective_local_action == "soft_challenge" ||
                                   effective_local_action == "pow_challenge" || config.sitewide_challenge ||
                                   (config.challenge_scope == "sensitive_only" && path_is_sensitive(config, request->path)) ||
                                   (config.response_action == "soft_challenge" && path_is_sensitive(config, request->path)) ||
                                   (config.response_action == "pow_challenge"));
    if (should_challenge) {
      state.metrics.challenged_requests++;
      const bool should_show_captcha =
          forced_soft_challenge || effective_local_action == "soft_challenge" ||
          (!forced_pow_challenge && effective_local_action != "pow_challenge" && config.response_action == "soft_challenge");
      const std::string body =
          should_show_captcha ? make_captcha_page(config, state, *request) : make_challenge_page(config, state, *request);
      if (shared_decision.has_value()) {
        headers.push_back({"X-GENWAF-Cluster-Decision", shared_decision->action});
      }
      if (!effective_local_action.empty()) {
        headers.push_back({"X-GENWAF-Local-Decision", effective_local_action});
      }
      if (!request->fingerprint_id.empty()) {
        headers.push_back({"X-GENWAF-Fingerprint", request->fingerprint_id});
      }
      const std::string response = html_response(403, body, keep_alive, headers);
      send_all(client_fd, response);
      if (!keep_alive) {
        break;
      }
      continue;
    }

    const bool cacheable = config.cache_enabled && request->method == "GET" && request->path.rfind("/static/", 0) == 0;
    if (cacheable) {
      if (const auto cached = get_cached_body(state, cache_key); cached.has_value()) {
        state.metrics.cache_hits++;
        const std::string response = cached.value();
        send_all(client_fd, response);
        if (!keep_alive) {
          break;
        }
        continue;
      }
      state.metrics.cache_misses++;
    }

    if (const auto backend = select_backend(state, *request); backend.has_value()) {
      BackendTarget active_target = backend.value();
      std::optional<std::string> proxied;
      const int attempts = std::max(0, active_target.retry_attempts) + 1;

      for (int attempt = 0; attempt < attempts; ++attempt) {
        proxied = proxy_to_backend(config, active_target, *request);
        if (proxied.has_value()) {
          mark_backend_result(state, active_target, true, "");
          break;
        }

        mark_backend_result(state, active_target, false, "passive upstream failure");
        if (attempt + 1 >= attempts) {
          break;
        }

        const auto retry_target = select_backend(state, *request);
        if (!retry_target.has_value() || backend_key(retry_target.value()) == backend_key(active_target)) {
          break;
        }
        active_target = retry_target.value();
      }

      if (!proxied.has_value()) {
        const std::string body = "{\"status\":\"upstream_error\",\"reason\":\"backend connect or read failed\"}";
        const std::string response = json_response(502, body, keep_alive);
        send_all(client_fd, response);
        if (!keep_alive) {
          break;
        }
        continue;
      }

      if (cacheable) {
        store_cached_body(state, config, cache_key, proxied.value(), config.cache_aggressive || config.cache_static);
      }
      send_all(client_fd, proxied.value());
      if (!keep_alive) {
        break;
      }
      continue;
    }

    const std::string body = build_application_body(*request);
    if (cacheable) {
      headers.push_back({"X-Cache", "MISS"});
    }
    const std::string response = json_response(200, body, keep_alive, headers);
    if (cacheable) {
      store_cached_body(state, config, cache_key, response, config.cache_aggressive || config.cache_static);
    }
    send_all(client_fd, response);

    if (!keep_alive) {
      break;
    }
  }

  close(client_fd);
}

void worker_loop(ConnectionQueue& queue, RuntimeState& state, const genwaf::EffectiveConfig& config) {
  while (g_running) {
    const auto task = pop_connection_task(queue);
    if (!task.has_value()) {
      return;
    }
    handle_connection(task->client_fd, task->client_addr, config, state);
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);

  const std::string_view config_path = extract_arg(argc, argv, "--config", "runtime/effective.json");
  const int explicit_port = extract_port(argc, argv, -1);

  try {
    const genwaf::EffectiveConfig config = genwaf::load_effective_config(std::string(config_path));
    RuntimeState state;
    state.challenge_secret = issue_secret();
    build_routing(state, config);
    const int port = explicit_port > 0 ? explicit_port : config.listen_port;

    const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
      throw std::runtime_error("failed to create server socket");
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      close(server_fd);
      throw std::runtime_error("failed to bind server socket");
    }
    if (listen(server_fd, 1024) < 0) {
      close(server_fd);
      throw std::runtime_error("failed to listen on server socket");
    }
    if (!set_nonblocking(server_fd)) {
      close(server_fd);
      throw std::runtime_error("failed to switch server socket to non-blocking mode");
    }
    const int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
      close(server_fd);
      throw std::runtime_error("failed to create epoll instance");
    }
    epoll_event listen_event{};
    listen_event.events = EPOLLIN;
    listen_event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &listen_event) != 0) {
      close(epoll_fd);
      close(server_fd);
      throw std::runtime_error("failed to register server socket with epoll");
    }

    std::cout << "[gendp] booting data-plane runtime\n";
    std::cout << "[gendp] " << genwaf::summarize(config) << "\n";
    std::cout << "[gendp] listening on :" << port << "\n";
    std::thread health_thread(health_loop, std::ref(state), config);
    std::thread observation_thread(observation_flush_loop, std::ref(state), config);
    ConnectionQueue connection_queue;
    const int worker_count = std::max(1, config.worker_threads);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(worker_count));
    for (int i = 0; i < worker_count; ++i) {
      workers.emplace_back(worker_loop, std::ref(connection_queue), std::ref(state), config);
    }

    std::array<epoll_event, 16> events{};
    while (g_running) {
      const int ready = epoll_wait(epoll_fd, events.data(), static_cast<int>(events.size()), 1000);
      if (ready < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (ready == 0) {
        continue;
      }
      for (int i = 0; i < ready; ++i) {
        if (events[static_cast<std::size_t>(i)].data.fd != server_fd) {
          continue;
        }
        while (g_running) {
          sockaddr_in client_addr{};
          socklen_t client_len = sizeof(client_addr);
          const int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
          if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              break;
            }
            if (errno == EINTR) {
              continue;
            }
            break;
          }

          if (!try_acquire_connection_slot(state, std::max(1, config.max_active_connections))) {
            state.metrics.shed_connections++;
            const std::string response = json_response(
                503, "{\"status\":\"busy\",\"reason\":\"max active connection limit reached\"}", false, {{"Retry-After", "1"}});
            send_all(client_fd, response);
            close(client_fd);
            log_if_enabled(state, config, "shed connection because max active connection limit was reached");
            continue;
          }

          push_connection_task(connection_queue, ConnectionTask{.client_fd = client_fd, .client_addr = client_addr});
        }
      }
    }

    stop_connection_queue(connection_queue);
    close(epoll_fd);
    close(server_fd);
    g_running = false;
    for (auto& worker : workers) {
      if (worker.joinable()) {
        worker.join();
      }
    }
    if (health_thread.joinable()) {
      health_thread.join();
    }
    if (observation_thread.joinable()) {
      observation_thread.join();
    }
  } catch (const std::exception& ex) {
    std::cerr << "[gendp] startup failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
