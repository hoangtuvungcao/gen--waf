#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct genwaf_xdp_config {
  __u32 enabled;
  __u32 drop_invalid_packets;
  __u32 strict_mode;
  __u32 per_ip_guard;
  __u32 allow_cf_only;
  __u32 allowlist_enabled;
  __u32 rate_limit_rps;
  __u32 burst;
};

struct genwaf_xdp_lpm_key {
  __u32 prefixlen;
  __u32 addr;
};

struct genwaf_rate_state {
  __u64 last_ns;
  __u32 tokens;
};

struct genwaf_xdp_stats {
  __u64 passed;
  __u64 dropped;
  __u64 overlimit;
  __u64 invalid;
  __u64 allowlisted;
};

enum genwaf_stat_index {
  GENWAF_STAT_PASS = 0,
  GENWAF_STAT_DROP = 1,
  GENWAF_STAT_OVERLIMIT = 2,
  GENWAF_STAT_INVALID = 3,
  GENWAF_STAT_ALLOWLIST = 4,
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct genwaf_xdp_config);
} genwaf_xdp_config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct genwaf_xdp_lpm_key);
  __type(value, __u8);
} genwaf_allowlist_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, struct genwaf_rate_state);
} genwaf_rate_limit_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct genwaf_xdp_stats);
} genwaf_stats_map SEC(".maps");

static __always_inline void bump_stat(enum genwaf_stat_index stat) {
  __u32 key = 0;
  struct genwaf_xdp_stats* stats = bpf_map_lookup_elem(&genwaf_stats_map, &key);
  if (!stats) {
    return;
  }

  switch (stat) {
    case GENWAF_STAT_PASS:
      __sync_fetch_and_add(&stats->passed, 1);
      break;
    case GENWAF_STAT_DROP:
      __sync_fetch_and_add(&stats->dropped, 1);
      break;
    case GENWAF_STAT_OVERLIMIT:
      __sync_fetch_and_add(&stats->overlimit, 1);
      break;
    case GENWAF_STAT_INVALID:
      __sync_fetch_and_add(&stats->invalid, 1);
      break;
    case GENWAF_STAT_ALLOWLIST:
      __sync_fetch_and_add(&stats->allowlisted, 1);
      break;
  }
}

static __always_inline int handle_ipv4(void* data, void* data_end) {
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > data_end) {
    return XDP_ABORTED;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    bump_stat(GENWAF_STAT_PASS);
    return XDP_PASS;
  }

  struct iphdr* iph = (void*)(eth + 1);
  if ((void*)(iph + 1) > data_end) {
    return XDP_ABORTED;
  }
  if (iph->ihl < 5) {
    return XDP_ABORTED;
  }
  if ((void*)iph + (iph->ihl * 4) > data_end) {
    return XDP_ABORTED;
  }

  __u32 key = 0;
  struct genwaf_xdp_config* cfg = bpf_map_lookup_elem(&genwaf_xdp_config_map, &key);
  if (!cfg || !cfg->enabled) {
    bump_stat(GENWAF_STAT_PASS);
    return XDP_PASS;
  }

  if (cfg->allowlist_enabled) {
    const struct genwaf_xdp_lpm_key allow_key = {
        .prefixlen = 32,
        .addr = iph->saddr,
    };
    if (bpf_map_lookup_elem(&genwaf_allowlist_map, &allow_key)) {
      bump_stat(GENWAF_STAT_ALLOWLIST);
      bump_stat(GENWAF_STAT_PASS);
      return XDP_PASS;
    }
    if (cfg->allow_cf_only) {
      bump_stat(GENWAF_STAT_DROP);
      return XDP_DROP;
    }
  }

  if (!cfg->per_ip_guard || cfg->rate_limit_rps == 0 || cfg->burst == 0) {
    bump_stat(GENWAF_STAT_PASS);
    return XDP_PASS;
  }

  const __u32 src = iph->saddr;
  struct genwaf_rate_state* state = bpf_map_lookup_elem(&genwaf_rate_limit_map, &src);
  const __u64 now = bpf_ktime_get_ns();

  if (!state) {
    struct genwaf_rate_state initial = {
        .last_ns = now,
        .tokens = cfg->burst > 0 ? cfg->burst - 1 : 0,
    };
    bpf_map_update_elem(&genwaf_rate_limit_map, &src, &initial, BPF_ANY);
    return XDP_PASS;
  }

  if (state->last_ns == 0) {
    state->last_ns = now;
  }

  if (now > state->last_ns) {
    const __u64 delta = now - state->last_ns;
    const __u64 refill = (delta * cfg->rate_limit_rps) / 1000000000ULL;
    if (refill > 0) {
      __u64 tokens = state->tokens + refill;
      state->tokens = tokens > cfg->burst ? cfg->burst : tokens;
      state->last_ns = now;
    }
  }

  if (state->tokens == 0) {
    bump_stat(GENWAF_STAT_OVERLIMIT);
    bump_stat(GENWAF_STAT_DROP);
    return XDP_DROP;
  }

  state->tokens -= 1;
  bump_stat(GENWAF_STAT_PASS);
  return XDP_PASS;
}

SEC("xdp")
int genwaf_xdp_ingress(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;

  const int rc = handle_ipv4(data, data_end);
  if (rc == XDP_ABORTED) {
    bump_stat(GENWAF_STAT_INVALID);
    __u32 key = 0;
    struct genwaf_xdp_config* cfg = bpf_map_lookup_elem(&genwaf_xdp_config_map, &key);
    if (cfg && cfg->drop_invalid_packets) {
      bump_stat(GENWAF_STAT_DROP);
      return XDP_DROP;
    }
    bump_stat(GENWAF_STAT_PASS);
    return XDP_PASS;
  }
  return rc;
}

char LICENSE[] SEC("license") = "GPL";
