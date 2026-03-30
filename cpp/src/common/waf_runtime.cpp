#include "genwaf/waf_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

namespace genwaf {

namespace {

std::string normalize(std::string value) {
  for (auto& ch : value) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return value;
}

int threshold_for(const EffectiveConfig& config) {
  if (config.waf_paranoia_level >= 4) {
    return 1;
  }
  if (config.waf_paranoia_level == 3) {
    return 2;
  }
  return 3;
}

std::vector<std::pair<std::string, int>> patterns_for(const EffectiveConfig& config) {
  std::vector<std::pair<std::string, int>> patterns = {
      {"<script", 3},
      {"%3cscript", 3},
      {"union select", 3},
      {"../", 3},
      {"' or 1=1", 3},
      {"sleep(", 2},
      {"benchmark(", 2},
  };

  if (config.crs_import_enabled) {
    patterns.push_back({"%2e%2e%2f", 3});
    patterns.push_back({"information_schema", 3});
  }

  return patterns;
}

}  // namespace

WAFResult evaluate_waf(const EffectiveConfig& config, const WAFInput& input) {
  WAFResult result;
  if (!config.waf_enabled) {
    return result;
  }

  result.threshold = threshold_for(config);

  std::string target = normalize(input.path + "|" + input.user_agent);
  for (const auto& [pattern, weight] : patterns_for(config)) {
    if (target.find(pattern) != std::string::npos) {
      result.score += weight;
      result.matched_patterns.push_back(pattern);
    }
  }

  if (config.fingerprint_http && input.user_agent.empty()) {
    result.score += 1;
    result.matched_patterns.push_back("missing_user_agent");
  }
  if (config.fingerprint_cookie && !input.has_cookie && input.sensitive_path) {
    result.score += 1;
    result.matched_patterns.push_back("missing_cookie_on_sensitive_path");
  }

  result.should_block = config.waf_mode != "detect_only" && result.score >= result.threshold;
  return result;
}

}  // namespace genwaf
