# Mô Tả Dự Án

GEN WAF là reverse proxy tự host tập trung vào bảo vệ origin cho website và API.

Dự án hướng tới một lối triển khai thực dụng:

- public traffic đi qua `GEN WAF` ở port `80`
- giao diện quản trị `genctl` chỉ mở nội bộ ở `127.0.0.1:90`
- backend thật của ứng dụng giữ tùy chỉnh theo hệ thống hiện có
- dễ đặt phía sau Cloudflare để ẩn IP origin và giảm áp lực lưu lượng xấu

Các năng lực chính:

- reverse proxy và health-check backend
- challenge cho các đường dẫn nhạy cảm
- rate limiting cục bộ
- WAF runtime cơ bản
- control plane để validate config, dựng effective config, và theo dõi trạng thái

Phạm vi phù hợp:

- website và API nhỏ đến vừa
- triển khai single-node production dễ vận hành
- hệ thống muốn giữ quyền tự chủ ở lớp bảo vệ origin

Phạm vi chưa nên quảng bá quá mức:

- không phải mạng edge toàn cầu
- không phải giải pháp chống DDoS Internet-scale độc lập

Đọc thêm tại:

- [`README.md`](README.md)
- [`docs/INSTALL_VPS.md`](docs/INSTALL_VPS.md)
- [`docs/SECURITY_ANALYSIS.vi.md`](docs/SECURITY_ANALYSIS.vi.md)
