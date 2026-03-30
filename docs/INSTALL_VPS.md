# Hướng Dẫn Cài Đặt VPS

Đây là luồng cài đặt production chính của dự án ở thời điểm hiện tại.

## Mô hình triển khai khuyến nghị

```text
Trình duyệt
  -> Cloudflare proxy
  -> GEN WAF trên VPS
  -> ứng dụng thật của bạn
```

## Chuẩn port của dự án

- port public của `gendp`: `80`
- port admin nội bộ của `genctl`: `90`
- port backend ứng dụng: tùy ý

`genctl` nên chỉ bind ở `127.0.0.1:90`.

## Điều kiện đầu vào

- Ubuntu 22.04 hoặc 24.04
- domain đã trỏ về VPS
- ứng dụng thật đã có sẵn ở một địa chỉ `host:port`
- ví dụ backend:
  - `127.0.0.1:8080`
  - `10.0.0.10:8080`

## Cài đặt sau khi clone repo

```bash
git clone <repo-url> gen_waf
cd gen_waf

sudo ./scripts/install-vps.sh \
  --domain app.example.com \
  --origin 10.0.0.10:8080 \
  --edge-mode cloudflare
```

## Điều script sẽ làm

- cài dependency hệ thống cần thiết
- build `genctl` và `gendp`
- render `/etc/genwaf/genwaf.yaml`
- compile `/var/lib/genwaf/effective.json`
- cài `systemd` service
- tự thử giải phóng port `80` và `90` nếu đang bị chiếm
- restart dịch vụ cho tới khi health check thành công hoặc báo lỗi

## Điều script cố ý không làm

- không nhúng mật khẩu root vào file hoặc script
- không lưu secret của bạn vào repo
- không dựng `sampleweb` trong flow production

## Sau khi cài xong

Kiểm tra service:

```bash
sudo systemctl status genwaf-gendp --no-pager
sudo systemctl status genwaf-genctl --no-pager
```

Kiểm tra health:

```bash
curl -fsS http://127.0.0.1:80/healthz
curl -fsS http://127.0.0.1:80/__genwaf/status
curl -fsS http://127.0.0.1:90/healthz
curl -fsS http://127.0.0.1:90/v1/effective
```

Chạy smoke:

```bash
./scripts/smoke-install.sh \
  --waf-url http://127.0.0.1:80 \
  --admin-url http://127.0.0.1:90 \
  --host app.example.com
```

## Nếu sửa cấu hình

```bash
sudo ./scripts/rebuild-effective.sh
sudo systemctl restart genwaf-genctl
sudo systemctl restart genwaf-gendp
```

## Bootstrap từ VPS trắng sau khi đã public GitHub

```bash
curl -fsSL https://raw.githubusercontent.com/<org>/<repo>/main/scripts/bootstrap-vps.sh | \
  sudo bash -s -- \
    --repo-url https://github.com/<org>/<repo>.git \
    --repo-ref main \
    --domain app.example.com \
    --origin 10.0.0.10:8080 \
    --edge-mode cloudflare
```

## Tài liệu liên quan

- [Cấu hình Cloudflare Flexible](CLOUDFLARE_FLEXIBLE.vi.md)
- [Tham chiếu cấu hình](CONFIG_REFERENCE.md)
- [Vận hành hệ thống](OPERATIONS.md)
