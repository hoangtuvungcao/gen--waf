#include "genwaf/effective_config.hpp"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>

#include <chrono>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string_view>
#include <thread>

#ifndef GENWAF_BPF_OBJECT_DEFAULT
#define GENWAF_BPF_OBJECT_DEFAULT "build/genwaf_xdp.bpf.o"
#endif

namespace {

struct XDPRuntimeConfig {
  uint32_t enabled = 0;
  uint32_t drop_invalid_packets = 0;
  uint32_t strict_mode = 0;
  uint32_t per_ip_guard = 0;
  uint32_t allow_cf_only = 0;
  uint32_t allowlist_enabled = 0;
  uint32_t rate_limit_rps = 0;
  uint32_t burst = 0;
};

struct XDPAllowlistKey {
  uint32_t prefixlen = 0;
  uint32_t addr = 0;
};

struct XDPStatsSnapshot {
  uint64_t passed = 0;
  uint64_t dropped = 0;
  uint64_t overlimit = 0;
  uint64_t invalid = 0;
  uint64_t allowlisted = 0;
};

std::string_view extract_arg(int argc, char** argv, std::string_view flag, std::string_view fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::string_view(argv[i]) == flag) {
      return argv[i + 1];
    }
  }
  return fallback;
}

bool has_flag(int argc, char** argv, std::string_view flag) {
  for (int i = 1; i < argc; ++i) {
    if (std::string_view(argv[i]) == flag) {
      return true;
    }
  }
  return false;
}

void write_json_array(std::ofstream& out, const std::vector<std::string>& values) {
  out << "[";
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i > 0) {
      out << ", ";
    }
    out << "\"" << values[i] << "\"";
  }
  out << "]";
}

void write_profile(const std::string& path, const genwaf::EffectiveConfig& config) {
  std::ofstream out(path);
  out << "{\n";
  out << "  \"name\": \"" << config.name << "\",\n";
  out << "  \"mode\": \"" << config.mode << "\",\n";
  out << "  \"xdp_enabled\": " << (config.xdp_enabled ? "true" : "false") << ",\n";
  out << "  \"xdp_mode\": \"" << config.xdp_mode << "\",\n";
  out << "  \"xdp_interface\": \"" << config.xdp_interface << "\",\n";
  out << "  \"xdp_attach_mode\": \"" << config.xdp_attach_mode << "\",\n";
  out << "  \"allow_cf_only\": " << (config.allow_cf_only ? "true" : "false") << ",\n";
  out << "  \"xdp_allowlist_entries\": " << config.xdp_allowlist_cidrs.size() << ",\n";
  out << "  \"xdp_allowlist_cidrs\": ";
  write_json_array(out, config.xdp_allowlist_cidrs);
  out << ",\n";
  out << "  \"drop_invalid_packets\": " << (config.drop_invalid_packets ? "true" : "false") << ",\n";
  out << "  \"per_ip_guard\": " << (config.per_ip_guard ? "true" : "false") << ",\n";
  out << "  \"rate_limit_rps\": " << config.rate_limit_rps << ",\n";
  out << "  \"rate_limit_burst\": " << config.rate_limit_burst << ",\n";
  out << "  \"response_action\": \"" << config.response_action << "\"\n";
  out << "}\n";
}

bool raise_memlock() {
  rlimit limit{};
  limit.rlim_cur = RLIM_INFINITY;
  limit.rlim_max = RLIM_INFINITY;
  return setrlimit(RLIMIT_MEMLOCK, &limit) == 0;
}

uint32_t attach_flags_for(const std::string& mode) {
  if (mode == "native") {
    return XDP_FLAGS_DRV_MODE;
  }
  return XDP_FLAGS_SKB_MODE;
}

bool parse_ipv4_cidr(const std::string& cidr, XDPAllowlistKey& key) {
  const std::size_t slash = cidr.find('/');
  if (slash == std::string::npos) {
    return false;
  }

  int prefix = 0;
  try {
    prefix = std::stoi(cidr.substr(slash + 1));
  } catch (...) {
    return false;
  }
  if (prefix < 0 || prefix > 32) {
    return false;
  }

  in_addr addr{};
  if (inet_pton(AF_INET, cidr.substr(0, slash).c_str(), &addr) != 1) {
    return false;
  }

  const uint32_t host_addr = ntohl(addr.s_addr);
  const uint32_t mask = prefix == 0 ? 0u : (0xffffffffu << (32 - prefix));
  key.prefixlen = static_cast<uint32_t>(prefix);
  key.addr = htonl(host_addr & mask);
  return true;
}

int configure_allowlist_map(bpf_object* obj, const genwaf::EffectiveConfig& config) {
  const int map_fd = bpf_object__find_map_fd_by_name(obj, "genwaf_allowlist_map");
  if (map_fd < 0) {
    std::cerr << "[genxdp-loader] failed to find genwaf_allowlist_map\n";
    return map_fd;
  }

  for (const auto& cidr : config.xdp_allowlist_cidrs) {
    XDPAllowlistKey key{};
    if (!parse_ipv4_cidr(cidr, key)) {
      std::cerr << "[genxdp-loader] invalid IPv4 allowlist CIDR: " << cidr << "\n";
      return -EINVAL;
    }
    const uint8_t allow = 1;
    if (bpf_map_update_elem(map_fd, &key, &allow, BPF_ANY) != 0) {
      std::cerr << "[genxdp-loader] failed to program allowlist CIDR: " << cidr << "\n";
      return -errno;
    }
  }
  return 0;
}

int configure_maps(bpf_object* obj, const genwaf::EffectiveConfig& config) {
  const int map_fd = bpf_object__find_map_fd_by_name(obj, "genwaf_xdp_config_map");
  if (map_fd < 0) {
    std::cerr << "[genxdp-loader] failed to find genwaf_xdp_config_map\n";
    return map_fd;
  }

  XDPRuntimeConfig runtime{};
  runtime.enabled = config.xdp_enabled ? 1u : 0u;
  runtime.drop_invalid_packets = config.drop_invalid_packets ? 1u : 0u;
  runtime.strict_mode = config.xdp_mode == "strict" ? 1u : 0u;
  runtime.per_ip_guard = config.per_ip_guard ? 1u : 0u;
  runtime.allow_cf_only = config.allow_cf_only ? 1u : 0u;
  runtime.allowlist_enabled = !config.xdp_allowlist_cidrs.empty() ? 1u : 0u;
  runtime.rate_limit_rps = config.rate_limit_rps > 0 ? static_cast<uint32_t>(config.rate_limit_rps) : 0u;
  runtime.burst = config.rate_limit_burst > 0 ? static_cast<uint32_t>(config.rate_limit_burst) : 0u;

  const uint32_t key = 0;
  if (bpf_map_update_elem(map_fd, &key, &runtime, BPF_ANY) != 0) {
    return -errno;
  }
  return configure_allowlist_map(obj, config);
}

int read_stats(bpf_object* obj, XDPStatsSnapshot& stats) {
  const int map_fd = bpf_object__find_map_fd_by_name(obj, "genwaf_stats_map");
  if (map_fd < 0) {
    std::cerr << "[genxdp-loader] failed to find genwaf_stats_map\n";
    return map_fd;
  }

  const uint32_t key = 0;
  if (bpf_map_lookup_elem(map_fd, &key, &stats) != 0) {
    return -errno;
  }
  return 0;
}

void print_stats_snapshot(const XDPStatsSnapshot& stats, int second) {
  std::cout << "[genxdp-loader] stats";
  if (second >= 0) {
    std::cout << " t=" << second << "s";
  }
  std::cout << " pass=" << stats.passed
            << " drop=" << stats.dropped
            << " overlimit=" << stats.overlimit
            << " invalid=" << stats.invalid
            << " allowlisted=" << stats.allowlisted << "\n";
}

int attach_xdp(const std::string& iface, const std::string& attach_mode, const std::string& object_path,
               const genwaf::EffectiveConfig& config, int stats_seconds) {
  if (iface.empty()) {
    std::cerr << "[genxdp-loader] xdp interface is empty; set origin.xdp.interface or pass --iface\n";
    return 1;
  }

  const unsigned int ifindex = if_nametoindex(iface.c_str());
  if (ifindex == 0) {
    std::cerr << "[genxdp-loader] interface not found: " << iface << "\n";
    return 1;
  }

  if (!raise_memlock()) {
    std::cerr << "[genxdp-loader] warning: failed to raise memlock; load may still fail\n";
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(nullptr);

  bpf_object* obj = bpf_object__open_file(object_path.c_str(), nullptr);
  if (!obj) {
    std::cerr << "[genxdp-loader] failed to open bpf object: " << object_path << "\n";
    return 1;
  }

  if (bpf_object__load(obj) != 0) {
    std::cerr << "[genxdp-loader] failed to load bpf object; check kernel permission/libbpf support\n";
    bpf_object__close(obj);
    return 1;
  }

  if (configure_maps(obj, config) != 0) {
    std::cerr << "[genxdp-loader] failed to configure XDP maps\n";
    bpf_object__close(obj);
    return 1;
  }

  bpf_program* prog = bpf_object__find_program_by_name(obj, "genwaf_xdp_ingress");
  if (!prog) {
    std::cerr << "[genxdp-loader] failed to find program genwaf_xdp_ingress\n";
    bpf_object__close(obj);
    return 1;
  }

  const int prog_fd = bpf_program__fd(prog);
  const uint32_t flags = attach_flags_for(attach_mode);
  const int rc = bpf_xdp_attach(static_cast<int>(ifindex), prog_fd, flags, nullptr);
  if (rc != 0) {
    std::cerr << "[genxdp-loader] attach failed on " << iface << ": " << std::strerror(-rc) << "\n";
    if (rc == -EPERM) {
      std::cerr << "[genxdp-loader] tip: this environment needs CAP_BPF/CAP_NET_ADMIN or root to attach XDP\n";
    }
    bpf_object__close(obj);
    return 1;
  }

  std::cout << "[genxdp-loader] attached XDP program to " << iface << " using " << attach_mode << " mode\n";
  if (stats_seconds > 0) {
    for (int second = 0; second < stats_seconds; ++second) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      XDPStatsSnapshot stats{};
      if (read_stats(obj, stats) == 0) {
        print_stats_snapshot(stats, second + 1);
      } else {
        std::cerr << "[genxdp-loader] failed to read XDP stats during watch window\n";
        break;
      }
    }
  }
  bpf_object__close(obj);
  return 0;
}

int detach_xdp(const std::string& iface, const std::string& attach_mode) {
  if (iface.empty()) {
    std::cerr << "[genxdp-loader] xdp interface is empty; set origin.xdp.interface or pass --iface\n";
    return 1;
  }

  const unsigned int ifindex = if_nametoindex(iface.c_str());
  if (ifindex == 0) {
    std::cerr << "[genxdp-loader] interface not found: " << iface << "\n";
    return 1;
  }

  const uint32_t flags = attach_flags_for(attach_mode);
  const int rc = bpf_xdp_detach(static_cast<int>(ifindex), flags, nullptr);
  if (rc != 0) {
    std::cerr << "[genxdp-loader] detach failed on " << iface << ": " << std::strerror(-rc) << "\n";
    if (rc == -EPERM) {
      std::cerr << "[genxdp-loader] tip: this environment needs CAP_BPF/CAP_NET_ADMIN or root to detach XDP\n";
    }
    return 1;
  }

  std::cout << "[genxdp-loader] detached XDP program from " << iface << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string_view config_path = extract_arg(argc, argv, "--config", "runtime/effective.json");
  const std::string_view output_path = extract_arg(argc, argv, "--output", "runtime/xdp-profile.json");
  const bool attach = has_flag(argc, argv, "--attach");
  const bool detach = has_flag(argc, argv, "--detach");
  int stats_seconds = 0;
  if (const std::string_view raw = extract_arg(argc, argv, "--stats-seconds", "0"); !raw.empty()) {
    stats_seconds = std::max(0, std::stoi(std::string(raw)));
  }

  try {
    const genwaf::EffectiveConfig config = genwaf::load_effective_config(std::string(config_path));
    const std::string iface = std::string(extract_arg(argc, argv, "--iface", config.xdp_interface));
    const std::string attach_mode = std::string(extract_arg(argc, argv, "--attach-mode", config.xdp_attach_mode));
    const std::string object_path = std::string(extract_arg(argc, argv, "--bpf-object", GENWAF_BPF_OBJECT_DEFAULT));

    std::cout << "[genxdp-loader] compiling xdp runtime profile\n";
    std::cout << "[genxdp-loader] " << genwaf::summarize(config) << "\n";
    write_profile(std::string(output_path), config);
    std::cout << "[genxdp-loader] wrote profile to " << output_path << "\n";
    std::cout << "[genxdp-loader] bpf object: " << object_path << "\n";

    if (detach) {
      return detach_xdp(iface, attach_mode);
    }
    if (attach) {
      return attach_xdp(iface, attach_mode, object_path, config, stats_seconds);
    }
    if (stats_seconds > 0) {
      std::cout << "[genxdp-loader] note: --stats-seconds only applies together with --attach\n";
    }

    std::cout << "[genxdp-loader] profile compile complete; pass --attach --iface <name> to attach\n";
  } catch (const std::exception& ex) {
    std::cerr << "[genxdp-loader] startup failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
