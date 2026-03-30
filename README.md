# GEN WAF

Mô tả ngắn:

> GEN WAF là reverse proxy tự host tập trung vào bảo vệ origin cho website và API, có challenge tích hợp, rate-limit, WAF cơ bản, và luồng vận hành thực dụng phía sau Cloudflare.

## Dự án này dành cho ai

GEN WAF phù hợp khi bạn cần:

- dựng một lớp bảo vệ origin tự host, gọn và dễ đọc
- giữ quyền kiểm soát challenge, routing, và hành vi bảo vệ
- chạy single-node production đơn giản trước, rồi mới mở rộng
- đặt hệ thống phía sau Cloudflare để ẩn IP origin và giảm áp lực DDoS

GEN WAF không nên được mô tả là giải pháp thay thế hoàn toàn cho một mạng edge toàn cầu.

## Thành phần chính

- `gendp`
  data plane C++ xử lý routing, challenge, rate-limit, WAF, health-check, và proxy
- `genctl`
  control plane Go để validate config, compile effective config, xem dashboard, status, và API điều hành
- `genedge`
  edge gateway phục vụ các flow lab cho `HTTP/1.1`, `HTTP/2`, `HTTP/3`
- `sampleweb`
  backend mẫu chỉ dùng cho development và benchmark, không phải phụ thuộc của flow cài production

## Chuẩn port của dự án

Đường production hiện được chuẩn hóa như sau:

- `GEN WAF public`: port `80`
- `GEN WAF admin / genctl`: `127.0.0.1:90`
- các port backend thật: tùy chỉnh theo hệ thống của bạn

Mục tiêu là để cách vận hành dễ nhớ, dễ kiểm tra, và dễ bàn giao hơn.

## Lối đi production chính

- [`configs/genwaf-production.yaml`](configs/genwaf-production.yaml)
  file mẫu production chuẩn
- [`configs/templates/single-node.vps.yaml.tmpl`](configs/templates/single-node.vps.yaml.tmpl)
  template cài đặt thật cho VPS
- [`scripts/install-vps.sh`](scripts/install-vps.sh)
  script cài đặt production từ repo đã clone
- [`scripts/bootstrap-vps.sh`](scripts/bootstrap-vps.sh)
  bootstrap cho VPS trắng sau khi repo đã public lên GitHub
- [`scripts/smoke-install.sh`](scripts/smoke-install.sh)
  script xác nhận hệ thống đã chạy đúng sau cài đặt
- [`scripts/rebuild-effective.sh`](scripts/rebuild-effective.sh)
  dựng lại effective config sau khi sửa YAML
- [`scripts/clean-generated.sh`](scripts/clean-generated.sh)
  dọn build/runtime/log phát sinh trước khi commit hoặc release

## Cài nhanh trên VPS

Sau khi clone repo:

```bash
sudo ./scripts/install-vps.sh \
  --domain app.example.com \
  --origin 10.0.0.10:8080 \
  --edge-mode cloudflare
```

Sau khi cài xong:

```bash
./scripts/smoke-install.sh \
  --waf-url http://127.0.0.1:80 \
  --admin-url http://127.0.0.1:90 \
  --host app.example.com
```

## Lưu ý bảo mật quan trọng

- không nhúng mật khẩu root vào script hoặc repo
- `genctl` nên chỉ bind ở `127.0.0.1:90`
- nếu dùng Cloudflare Flexible, đoạn Cloudflare -> origin vẫn là HTTP
- nếu record DNS chưa bật proxy của Cloudflare, IP VPS vẫn có thể bị lộ trực tiếp

Phân tích chi tiết:

- [Phân tích bảo mật của dự án](docs/SECURITY_ANALYSIS.vi.md)
- [Chính sách bảo mật](SECURITY.md)

## Tài liệu chính

- [Mô tả dự án](DESCRIPTION.md)
- [Hướng dẫn cài đặt VPS](docs/INSTALL_VPS.md)
- [Hướng dẫn Cloudflare Flexible](docs/CLOUDFLARE_FLEXIBLE.vi.md)
- [Tham chiếu cấu hình](docs/CONFIG_REFERENCE.md)
- [Hướng dẫn vận hành](docs/OPERATIONS.md)
- [Kiến trúc hệ thống](docs/ARCHITECTURE.md)
- [Luồng development và lab](docs/DEVELOPMENT.md)
- [Phân tích bảo mật](docs/SECURITY_ANALYSIS.vi.md)

## License

Dự án hiện dùng giấy phép [MIT](LICENSE).

## Luồng development

```bash
make build
make validate
make test
```

## Ghi chú để public repo

- flow production không phụ thuộc `sampleweb`
- `sampleweb` vẫn được giữ lại làm công cụ dev và benchmark
- build/runtime/generated files nên được dọn bằng `./scripts/clean-generated.sh` trước khi push
