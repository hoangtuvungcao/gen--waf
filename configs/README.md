# Cấu Trúc Thư Mục `configs/`

- `genwaf-production.yaml`
  Cấu hình production mẫu, dễ đọc và dùng làm baseline.

- `templates/single-node.vps.yaml.tmpl`
  Template được render khi cài thật lên VPS.

- `profiles/`
  Hồ sơ lab và development phục vụ regression, benchmark, và smoke test.

- `benchmarks/`
  Profile benchmark và threshold dùng cho CI hoặc kiểm tra hiệu năng cục bộ.

Nên đọc thêm:

- [`../docs/CONFIG_REFERENCE.md`](../docs/CONFIG_REFERENCE.md)
- [`../docs/CONFIG_FULL_REFERENCE.vi.md`](../docs/CONFIG_FULL_REFERENCE.vi.md)
