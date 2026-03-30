# Tham Chiếu Cấu Hình Đầy Đủ

Tài liệu này là bản diễn giải đầy đủ hơn cho cấu hình production của GEN WAF.

Điểm bắt đầu thực tế nhất:

- file mẫu dễ đọc: [`../configs/genwaf-production.yaml`](../configs/genwaf-production.yaml)
- template VPS được render khi cài: [`../configs/templates/single-node.vps.yaml.tmpl`](../configs/templates/single-node.vps.yaml.tmpl)

## 1. Chuẩn vận hành hiện tại

- `gendp` public ở port `80`
- `genctl` chỉ mở nội bộ ở `127.0.0.1:90`
- backend ứng dụng thật tự chọn `host:port`

## 2. Cấu trúc tổng thể

```yaml
system:
edge:
origin:
routing:
waf:
rate_limit:
bot_defense:
behavior:
automation:
cluster:
storage:
observability:
```

## 3. Diễn giải theo từng nhóm

### `system`

- `name`: tên hệ thống xuất hiện trong log, dashboard, effective config
- `deployment`: hiện nên để `single` cho production đơn giản
- `mode`: mode khởi động mặc định, thường là `normal`
- `auto_mode`: cho phép control plane tự nâng mode khi thấy tín hiệu xấu

### `edge.cloudflare`

- `enabled`: bật khi domain đi sau Cloudflare proxy
- `lock_origin_to_cf`: chỉ chấp nhận traffic đi qua Cloudflare
- `trust_cf_headers`: đọc header Cloudflare để lấy IP client thật
- `cache_static`: cho phép tận dụng cache ở lớp ứng dụng khi phù hợp

Khuyến nghị:

- `direct`: đặt cả 3 field đầu là `false`
- `cloudflare`: đặt cả 3 field đầu là `true`

### `origin.xdp`

- `enabled`: bật hoặc tắt lớp XDP
- `mode`: `off`, `adaptive`, hoặc `strict`
- `interface`: card mạng public của VPS, ví dụ `eth0`
- `attach_mode`: mode attach của XDP, baseline hiện dùng `generic`
- `sync_from_controller`: sync cấu hình XDP từ control plane
- `allow_cf_only`: chỉ hữu ích khi thật sự dùng XDP để khóa nguồn vào
- `allowlist_cidrs`: allowlist IPv4/IPv6 nếu cần
- `drop_invalid_packets`: bỏ packet lỗi sớm
- `per_ip_guard`: guard theo IP ở tầng packet

Khuyến nghị production đầu tiên:

- `enabled: false`
- `mode: off`

### `origin.proxy`

- `engine`: engine data plane, hiện là `gendp`
- `listen_port`: port public cố định của dự án, hiện là `80`
- `real_ip_from_edge_only`: chỉ tin IP thật từ edge tin cậy
- `cache_enabled`: bật cache GET tĩnh khi phù hợp
- `keepalive`: giữ kết nối với client và upstream
- `http_parser`: parser HTTP đang dùng
- `worker_model`: mô hình xử lý request
- `max_active_connections`: giới hạn số kết nối đồng thời
- `max_keepalive_requests`: giới hạn số request mỗi kết nối keep-alive
- `header_read_timeout_ms`: chống slowloris
- `max_request_bytes`: chặn request quá lớn
- `max_response_cache_entries`: giới hạn cache response RAM
- `upstream_connect_timeout_ms`: timeout kết nối backend
- `upstream_read_timeout_ms`: timeout đọc phản hồi backend

### `routing.backend_pools`

Mỗi `backend_pool` mô tả một nhóm upstream:

- `name`: tên pool
- `balance`: chiến lược phân phối, ví dụ `round_robin`
- `health_check_path`: endpoint kiểm tra sức khỏe, nên có `/healthz`
- `health_check_interval_ms`: chu kỳ health check
- `health_check_timeout_ms`: timeout health check
- `unhealthy_threshold`: số lần lỗi liên tiếp để đánh dấu unhealthy
- `healthy_threshold`: số lần thành công liên tiếp để khôi phục healthy
- `fail_timeout_ms`: thời gian chờ trước khi thử lại upstream lỗi
- `retry_attempts`: số lần retry upstream
- `servers[].id`: định danh node backend
- `servers[].address`: địa chỉ `host:port` thật
- `servers[].weight`: trọng số load balancing

### `routing.virtual_hosts`

- `domains`: các domain public GEN WAF phục vụ
- `default_pool`: pool mặc định cho host đó
- `path_rules`: rule theo path nếu cần tách route sâu hơn

Ví dụ:

```yaml
virtual_hosts:
  - domains:
      - app.example.com
    default_pool: main_pool
    path_rules: []
```

### `waf`

- `enabled`: bật WAF runtime
- `engine`: engine hiện tại
- `ruleset`: bộ rule mặc định
- `paranoia_level`: mức nghiêm ngặt
- `mode`: kiểu hành động, baseline hiện dùng `anomaly_block`
- `compatibility.crs_import`: bật pattern tương thích kiểu CRS cơ bản

### `rate_limit`

- `enabled`: bật rate limit
- `backend`: `local` cho single-node
- `requests_per_second`: ngưỡng RPS cơ bản
- `burst`: dung lượng burst
- `max_tracked_ips`: số IP tối đa giữ state
- `sensitive_paths`: các đường dẫn cần nhạy hơn

Baseline khuyến nghị:

- `requests_per_second: 60`
- `burst: 180`

### `bot_defense`

- `enabled`: bật lớp challenge
- `default_action`: hành động mặc định, nên là `allow`
- `js_challenge`: bật JS challenge
- `replay_protection`: chống replay token
- `challenge_difficulty`: độ khó challenge
- `challenge_token_cache_entries`: kích thước cache token
- `challenge_pass_ttl_seconds`: thời gian cho phép sau khi vượt challenge
- `pow.enabled`: bật proof-of-work
- `pow.provider`: nhà cung cấp challenge
- `pow.mode`: `adaptive` là baseline hợp lý

### `behavior`

- `enabled`: bật lớp tín hiệu hành vi
- `decision_cache_ttl`: TTL cho decision cache
- `max_decision_entries`: số decision tối đa
- `fingerprinting.tls`: fingerprint TLS
- `fingerprinting.http`: fingerprint HTTP
- `fingerprinting.cookie`: fingerprint cookie
- `fingerprinting.session`: fingerprint theo session

Khuyến nghị thực dụng:

- `tls: false` nếu chưa chắc luồng TLS fingerprint ở edge
- giữ `http`, `cookie`, `session` ở `true`

### `automation`

- `enabled`: bật tự động điều chỉnh
- `auto_tune_from_host`: lấy tín hiệu host để hỗ trợ tự điều chỉnh
- `escalate_on.*`: các ngưỡng kích hoạt nâng mode
- `cooldown_minutes`: thời gian hạ mode sau khi ổn
- `actions.elevated.*`: chính sách khi lên `elevated`
- `actions.under_attack.*`: chính sách khi lên `under_attack`

### `cluster`

Single-node production nên để:

- `sync_enabled: false`
- `shared_decisions: false`
- `shared_rate_limit_path`, `local_decision_path`, `local_observation_path` nằm trong `/var/lib/genwaf`

Giữ các field này dù chạy một node giúp dễ nâng cấp multi-node về sau.

### `storage`

- `redis_enabled`: bật Redis nếu chạy cluster hoặc state chia sẻ
- `redis_address`: địa chỉ Redis
- `redis_password`: chỉ dùng khi có secret thật
- `redis_db`: logical DB của Redis
- `redis_prefix`: tiền tố key
- `postgres_enabled`: hiện mặc định để `false`

### `observability`

- `metrics`: bật Prometheus metrics
- `logs`: bật log runtime
- `traces`: trace sâu, mặc định để `false`
- `dashboard`: bật dashboard của `genctl`

## 4. Mẫu cấu hình single-node thực dụng

```yaml
system:
  name: genwaf-production
  deployment: single
  mode: normal
  auto_mode: true

edge:
  cloudflare:
    enabled: true
    lock_origin_to_cf: true
    trust_cf_headers: true
    cache_static: true

origin:
  xdp:
    enabled: false
    mode: off
    interface: eth0
    attach_mode: generic
    sync_from_controller: false
    allow_cf_only: false
    allowlist_cidrs: []
    drop_invalid_packets: true
    per_ip_guard: false
  proxy:
    engine: gendp
    listen_port: 80
    real_ip_from_edge_only: true

routing:
  backend_pools:
    - name: main_pool
      balance: round_robin
      health_check_path: /healthz
      servers:
        - id: origin-1
          address: 127.0.0.1:8080
          weight: 1
  virtual_hosts:
    - domains:
        - app.example.com
      default_pool: main_pool
      path_rules: []
```

## 5. Quy trình sửa cấu hình an toàn

1. Sửa `/etc/genwaf/genwaf.yaml`
2. Validate bằng `genctl validate`
3. Dựng lại `effective.json`
4. Restart `genctl` và `gendp`
5. Chạy smoke test lại

## 6. Các lỗi cấu hình thường gặp

- đi sau Cloudflare nhưng quên bật `enabled`, `lock_origin_to_cf`, `trust_cf_headers`
- dùng `Flexible` nhưng origin lại ép redirect HTTP -> HTTPS
- backend không có `/healthz` nên pool bị đánh dấu unhealthy
- mở `genctl` ra Internet thay vì chỉ giữ ở `127.0.0.1:90`
- bật XDP quá sớm khi flow HTTP chưa ổn định

## 7. Tài liệu liên quan

- [`INSTALL_VPS.md`](INSTALL_VPS.md)
- [`CONFIG_REFERENCE.md`](CONFIG_REFERENCE.md)
- [`CLOUDFLARE_FLEXIBLE.vi.md`](CLOUDFLARE_FLEXIBLE.vi.md)
- [`SECURITY_ANALYSIS.vi.md`](SECURITY_ANALYSIS.vi.md)
