# Luồng Development Và Lab

Production path của dự án đã được tách rõ. Thư mục và script lab vẫn được giữ lại để phục vụ:

- development cục bộ
- benchmark
- regression
- giao thức edge
- thử nghiệm multi-node

## Build

```bash
make build
```

## Validate

```bash
make validate
```

## Regression

```bash
make test
```

## Edge protocol smoke

```bash
make smoke
```

## Các script lab còn giữ lại

- [`scripts/regression.sh`](../scripts/regression.sh)
- [`scripts/edge_protocol_smoke.sh`](../scripts/edge_protocol_smoke.sh)
- [`scripts/benchmark_suite.sh`](../scripts/benchmark_suite.sh)
- [`scripts/benchmark_cluster_redis_native.sh`](../scripts/benchmark_cluster_redis_native.sh)
- [`scripts/product_stack_redis_smoke.sh`](../scripts/product_stack_redis_smoke.sh)

## Vai trò của `sampleweb`

`sampleweb` vẫn được giữ để:

- test UI
- test challenge
- benchmark và regression

Nhưng flow production không phụ thuộc vào `sampleweb`.
