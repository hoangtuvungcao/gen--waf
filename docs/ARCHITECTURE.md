# Kiến Trúc Hệ Thống

## Luồng production đơn giản nhất

```text
Client
  -> Cloudflare hoặc edge tin cậy
  -> GEN WAF (gendp)
  -> ứng dụng thật
```

## Thành phần cốt lõi

### `gendp`

Vai trò:

- reverse proxy
- routing theo host/path
- challenge
- rate-limit
- WAF runtime
- health-check backend

### `genctl`

Vai trò:

- validate YAML
- compile effective config
- giữ status và dashboard
- expose API nội bộ cho vận hành

### `genedge`

Vai trò:

- component lab để terminate `HTTP/1.1`, `HTTP/2`, `HTTP/3`
- không phải phụ thuộc của flow production tối thiểu

### `sampleweb`

Vai trò:

- backend mẫu cho dev, benchmark, regression
- không thuộc đường cài production thật

## Chuẩn deploy hiện tại

### Public

- `gendp` ở port `80`

### Nội bộ

- `genctl` ở `127.0.0.1:90`

### Upstream

- app thật ở port riêng của ứng dụng

## Runtime state

Dù chạy single-node, hệ thống vẫn giữ layout state ổn định:

- `/var/lib/genwaf/effective.json`
- `/var/lib/genwaf/cluster-decisions.json`
- `/var/lib/genwaf/node-observations.json`
- `/var/lib/genwaf/cluster-rate-limits.json`
- `/var/lib/genwaf/controller-state.json`

Điều này giúp sau này nâng cấp lên luồng phức tạp hơn ít phải đổi cấu trúc thư mục.
