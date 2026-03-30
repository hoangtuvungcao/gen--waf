#pragma once

#include <string>
#include <vector>

#include "genwaf/effective_config.hpp"

namespace genwaf {

struct WAFInput {
  std::string path;
  std::string user_agent;
  bool has_cookie = false;
  bool sensitive_path = false;
};

struct WAFResult {
  int score = 0;
  int threshold = 0;
  bool should_block = false;
  std::vector<std::string> matched_patterns;
};

WAFResult evaluate_waf(const EffectiveConfig& config, const WAFInput& input);

}  // namespace genwaf
