# Chính Sách Bảo Mật

## Mức độ phù hợp hiện tại

GEN WAF phù hợp nhất cho:

- bảo vệ origin của website hoặc API nhỏ đến vừa
- lớp reverse proxy tự host phía sau Cloudflare hoặc một edge proxy mạnh
- môi trường single-node hoặc practical multi-node trong phạm vi vừa phải

GEN WAF hiện chưa nên được mô tả là giải pháp chống DDoS Internet-scale độc lập.

## Cách báo lỗi bảo mật

Nếu bạn phát hiện vấn đề bảo mật, không nên mở issue công khai ngay lập tức.

Hãy gửi báo cáo riêng cho maintainer của dự án kèm:

- mô tả lỗi
- điều kiện tái hiện
- ảnh hưởng thực tế
- đề xuất hướng khắc phục nếu có

## Nguyên tắc vận hành an toàn

- không nhúng mật khẩu root, token, hay secret vào script hoặc repo
- không public `genctl` ra Internet nếu không có lớp bảo vệ bổ sung
- ưu tiên đặt `genctl` ở `127.0.0.1:90`
- nếu dùng Cloudflare Flexible, phải hiểu rằng đoạn Cloudflare -> origin là HTTP
- nếu không có nhu cầu thực sự, giữ `XDP` ở trạng thái tắt cho đến khi HTTP path đã ổn định

## Tài liệu phân tích bảo mật

Xem thêm:

- [`docs/SECURITY_ANALYSIS.vi.md`](docs/SECURITY_ANALYSIS.vi.md)
