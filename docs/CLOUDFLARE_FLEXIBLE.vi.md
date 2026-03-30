# Hướng Dẫn Cấu Hình Cloudflare Flexible Cho GEN WAF

Tài liệu này dành cho trường hợp:

- domain đi qua proxy của Cloudflare
- trình duyệt truy cập HTTPS
- Cloudflare kết nối về VPS qua HTTP port `80`

## 1. Flexible là gì

Theo tài liệu chính thức của Cloudflare về SSL/TLS encryption modes, `Flexible` nghĩa là:

- visitor -> Cloudflare: HTTPS
- Cloudflare -> origin: HTTP

Điều này giúp:

- người dùng cuối thấy site là HTTPS
- record được proxy qua Cloudflare nên IP origin được ẩn tốt hơn
- Cloudflare đứng trước để lọc và hấp thụ nhiều loại lưu lượng rác tốt hơn

Nhưng cần hiểu rất rõ:

- đoạn từ Cloudflare về VPS **không có TLS**
- nếu bạn cần end-to-end encryption, hãy dùng `Full` hoặc `Full (strict)` thay vì `Flexible`

## 2. Khi nào nên dùng Flexible

Nên dùng khi:

- bạn muốn triển khai nhanh
- origin hiện chỉ mở HTTP port `80`
- chấp nhận việc Cloudflare -> origin là HTTP

Không nên dùng khi:

- bạn bắt buộc phải mã hóa toàn tuyến
- có yêu cầu compliance nghiêm ngặt
- backend/origin đã sẵn sàng TLS thật

## 3. Cấu hình Cloudflare khuyến nghị

### 3.1. DNS

Trong Cloudflare DNS:

- tạo record `A` hoặc `AAAA` cho domain về IP VPS
- bật trạng thái `Proxied` màu cam

Nếu record để `DNS only`, IP origin sẽ lộ trực tiếp và bạn mất lớp proxy của Cloudflare.

### 3.2. SSL/TLS mode

Trong dashboard Cloudflare:

- vào `SSL/TLS`
- chọn `Overview`
- đặt mode là `Flexible`

### 3.3. Edge certificate

Để visitor vào site bằng HTTPS ổn định:

- bật Universal SSL hoặc edge certificate phù hợp

### 3.4. Luôn ưu tiên HTTPS ở phía người dùng

Theo tài liệu chính thức của Cloudflare về `Enforce HTTPS connections`, nếu site của bạn sẵn sàng cho người dùng cuối bằng HTTPS thì nên:

- bật `Always Use HTTPS`
- cân nhắc bật `Automatic HTTPS Rewrites`

Nhưng với `Flexible`, phải tránh cấu hình redirect sai ở origin.

## 4. Cấu hình GEN WAF tương ứng

Khi cài với:

```bash
sudo ./scripts/install-vps.sh \
  --domain app.example.com \
  --origin 10.0.0.10:8080 \
  --edge-mode cloudflare
```

installer sẽ render cấu hình theo hướng:

- `cloudflare.enabled: true`
- `lock_origin_to_cf: true`
- `trust_cf_headers: true`
- `real_ip_from_edge_only: true`
- `listen_port: 80`

Điều này giúp GEN WAF:

- chỉ tin lưu lượng đi qua Cloudflare
- đọc IP thật của client từ header Cloudflare
- chạy public ở port `80`, đúng với Flexible mode

## 5. Tránh redirect loop

Đây là lỗi cấu hình phổ biến nhất với Flexible.

Nếu origin hoặc upstream ép redirect `http -> https` một cách cứng nhắc, bạn có thể tạo vòng lặp:

```text
visitor -> https -> Cloudflare
Cloudflare -> http -> origin
origin -> redirect https
Cloudflare -> http -> origin
...
```

Khuyến nghị:

- để Cloudflare chịu trách nhiệm HTTPS phía ngoài
- không bật redirect HTTP -> HTTPS vô điều kiện ở origin khi đang dùng Flexible
- sau mỗi thay đổi, test lại bằng trình duyệt thật và `curl`

## 6. Tăng khả năng bảo vệ máy chủ bằng Cloudflare

Những cấu hình nên xem thêm trong Cloudflare:

- bật proxy cho record DNS
- dùng WAF/rules của Cloudflare nếu gói hiện có hỗ trợ
- bật rate limiting/rules ở Cloudflare cho path nhạy cảm
- giảm bề mặt công khai của VPS, chỉ mở port cần thiết
- không mở `genctl` ra Internet

GEN WAF và Cloudflare nên bổ trợ nhau:

- Cloudflare xử lý edge, ẩn IP, và giảm bớt traffic xấu từ bên ngoài
- GEN WAF bảo vệ origin ở lớp gần ứng dụng hơn

## 7. Checklist triển khai

### Trên Cloudflare

- record DNS để `Proxied`
- SSL/TLS mode = `Flexible`
- edge certificate hoạt động
- cân nhắc `Always Use HTTPS`
- cân nhắc `Automatic HTTPS Rewrites`

### Trên VPS

- `gendp` nghe ở port `80`
- `genctl` giữ ở `127.0.0.1:90`
- backend thật trả được `/healthz`
- firewall không public port `90`

## 8. Nguồn chính thức của Cloudflare

Tài liệu chính thức đã dùng để viết phần này:

- SSL/TLS encryption modes:
  https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/
- Enforce HTTPS connections:
  https://developers.cloudflare.com/ssl/edge-certificates/encrypt-visitor-traffic/

Các trang trên có thể thay đổi giao diện theo thời gian, nhưng đây là nguồn chính thức nên nên ưu tiên đối chiếu tại đây khi cấu hình thực tế.
