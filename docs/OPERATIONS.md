# Hướng Dẫn Vận Hành

## Chuẩn service production

- `genwaf-gendp`
  data plane public ở port `80`
- `genwaf-genctl`
  control plane nội bộ ở `127.0.0.1:90`

## Quản lý service

```bash
sudo systemctl status genwaf-gendp --no-pager
sudo systemctl status genwaf-genctl --no-pager

sudo systemctl restart genwaf-genctl
sudo systemctl restart genwaf-gendp
```

## Health endpoint

- WAF health: `http://127.0.0.1:80/healthz`
- WAF status: `http://127.0.0.1:80/__genwaf/status`
- Admin health: `http://127.0.0.1:90/healthz`
- Admin status: `http://127.0.0.1:90/v1/status`
- Admin effective: `http://127.0.0.1:90/v1/effective`
- Admin dashboard: `http://127.0.0.1:90/dashboard`
- Admin metrics: `http://127.0.0.1:90/metrics`

## Log

```bash
sudo journalctl -u genwaf-gendp -f
sudo journalctl -u genwaf-genctl -f
```

## Quy trình an toàn khi sửa cấu hình

1. sửa `/etc/genwaf/genwaf.yaml`
2. dựng lại effective config
3. restart service
4. chạy smoke

```bash
sudo ./scripts/rebuild-effective.sh
sudo systemctl restart genwaf-genctl
sudo systemctl restart genwaf-gendp

./scripts/smoke-install.sh \
  --waf-url http://127.0.0.1:80 \
  --admin-url http://127.0.0.1:90 \
  --host app.example.com
```

## Runtime state

Mặc định runtime nằm ở `/var/lib/genwaf`:

- `effective.json`
- `cluster-decisions.json`
- `node-observations.json`
- `cluster-rate-limits.json`
- `controller-state.json`

## Truy cập dashboard an toàn

Không nên mở port `90` ra Internet. Hãy dùng SSH tunnel:

```bash
ssh -L 9090:127.0.0.1:90 user@your-vps
```

Sau đó mở:

```text
http://127.0.0.1:9090/dashboard
```

## Monitoring

Nếu cần Prometheus cục bộ:

```bash
./scripts/setup_prometheus.sh install
./scripts/setup_prometheus.sh config
./scripts/setup_prometheus.sh start
```

File dashboard Grafana có sẵn ở:

- [`docs/GRAFANA_DASHBOARD.json`](GRAFANA_DASHBOARD.json)
