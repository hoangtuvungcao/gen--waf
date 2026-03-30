# Tham Chiếu Cấu Hình

## Hai entry point production quan trọng

- [`configs/genwaf-production.yaml`](../configs/genwaf-production.yaml)
  baseline production dễ đọc
- [`configs/templates/single-node.vps.yaml.tmpl`](../configs/templates/single-node.vps.yaml.tmpl)
  template được render khi cài lên VPS

## Chuẩn hóa để dễ bảo trì

Dự án hiện chuẩn hóa:

- `gendp` public ở port `80`
- `genctl` nội bộ ở `127.0.0.1:90`
- backend thật tùy chỉnh theo ứng dụng

Điểm này giúp:

- tài liệu nhất quán hơn
- dễ kiểm tra nhanh khi vận hành
- giảm nhầm lẫn khi bàn giao

## Nhóm field quan trọng

### 1. `edge.cloudflare`

- `enabled`
  bật khi hệ thống chạy sau Cloudflare
- `lock_origin_to_cf`
  chặn truy cập origin trực tiếp
- `trust_cf_headers`
  tin các header Cloudflare để lấy IP thật

### 2. `origin.proxy`

- `listen_port`
  hiện được chuẩn hóa là `80`
- `real_ip_from_edge_only`
  nên bật khi chạy sau Cloudflare
- `max_active_connections`
  giới hạn để tránh giữ quá nhiều kết nối
- `header_read_timeout_ms`
  giúp giảm slowloris
- `upstream_connect_timeout_ms`
  timeout kết nối backend

### 3. `routing`

Ví dụ production đơn giản nhất:

```yaml
routing:
  backend_pools:
    - name: main_pool
      servers:
        - id: origin-1
          address: 10.0.0.10:8080
```

### 4. `rate_limit`

Baseline production hiện dùng:

- `backend: local`
- `requests_per_second: 60`
- `burst: 180`
- danh sách path nhạy cảm cho challenge/WAF

### 5. `cluster`

Single-node production vẫn giữ các đường dẫn state ở `/var/lib/genwaf/*` để:

- cấu trúc runtime ổn định
- sau này nâng cấp multi-node dễ hơn

## Mode cài đặt

### `--edge-mode direct`

Dùng khi:

- client hoặc load balancer đi thẳng vào VPS
- không dùng Cloudflare proxy

### `--edge-mode cloudflare`

Dùng khi:

- domain đang bật proxy màu cam của Cloudflare
- bạn muốn Cloudflare ẩn IP origin và giảm tải tốt hơn

## Nơi chỉnh cấu hình sau khi cài

- YAML chính: `/etc/genwaf/genwaf.yaml`
- effective config: `/var/lib/genwaf/effective.json`
- env cho systemd: `/etc/genwaf/genwaf.env`
