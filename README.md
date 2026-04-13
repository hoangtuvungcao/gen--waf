# GEN WAF Quick Start (Binary Distribution)

This folder contains pre-built binaries and configuration templates for GEN WAF. You can deploy it without building from source.

## 📋 System Requirements

- **OS**: Ubuntu 22.04 LTS or newer (Kernel 5.15+ strongly recommended for XDP).
- **CPU**: x86_64 architecture.
- **Dependencies**: 
  ```bash
  sudo apt-get update
  sudo apt-get install -y libssl3 libhiredis1.1 libelf1 zlib1g
  ```
- **External**: Redis 6.0+ (Optional, required for cluster features).

## 🚀 Installation & Running

### 1. Extract the folder
If you just downloaded this, ensure you are in the `release/` directory.

### 2. Prepare your VPS
If this is a fresh VPS, run the setup script to install all dependencies (OpenSSL, Redis, libbpf, etc.):

```bash
chmod +x scripts/*.sh
sudo ./scripts/setup-vps.sh
```

### 3. Configure your system
Choose the configuration template that fits your deployment:
- **Single Node**: Use `config/genwaf-single.yaml` (Default).
- **Cluster/Multi-Node**: Use `config/genwaf-cluster.yaml`.

To use a specific config, copy it to `config/genwaf.yaml`:
```bash
cp config/genwaf-single.yaml config/genwaf.yaml
```

If you make changes to `genwaf.yaml`, you **must** update the effective configuration used by the Data Plane:
```bash
./bin/genctl compile -config config/genwaf.yaml -output config/effective.json
```

## 🛡️ Built-in Protection Rules
GEN WAF comes with a high-performance ruleset (`gen_policy_v1`) enabled by default:
- **SQL Injection**: Detects common patterns like `union select`, `' or 1=1`, `sleep(`, `benchmark(`.
- **Cross-Site Scripting (XSS)**: Detects `<script`, `%3cscript`.
- **Path Traversal**: Detects `../`, `%2e%2e%2f`.
- **Sensitive Path Guard**: Automatic rate-limiting on `/login`, `/admin`, `/api/auth`.
- **Behavioral Analysis**: Detects missing User-Agents or suspicious cookie-less requests to sensitive paths.

### 4. Start the services
You can use the provided script to start both the Data Plane (`gendp`) and the Control Plane (`genctl`).

```bash
chmod +x bin/*
./scripts/start.sh
```

### 5. Verify
Check the logs to ensure everything is running:
- `logs/gendp.log`: Data plane logs (proxy traffic).
- `logs/genctl.log`: Control plane logs (dashboard & cluster sync).

The dashboard will be available at `http://127.0.0.1:8080/dashboard`.

## 🛡️ High-Performance XDP Protection (L4)
GEN WAF includes kernel-level packet filtering via XDP. This allows blocking millions of packets per second with minimal CPU usage.

**To enable XDP:**
1. Ensure your kernel supports XDP (Ubuntu 22.04+ is recommended).
2. Run the management script:
```bash
sudo ./scripts/xdp-manage.sh attach eth0
```
3. Verify status:
```bash
sudo ./scripts/xdp-manage.sh status eth0
```

## ☁️ Cloudflare Setup (MANDATORY STEPS)
To ensure the best protection and avoid "Error 521", follow these steps exactly:

1. **DNS Settings**:
   - Add an `A` record for your domain pointing to your VPS IP.
   - Ensure the "Proxy status" is **Proxied** (Orange Cloud 🟠).
2. **SSL/TLS Menu**:
   - Change "SSL/TLS encryption mode" to **Flexible**.
3. **WAF Configuration** (`config/genwaf.yaml`):
   - Set `cloudflare.enabled: true`.
   - Set `cloudflare.lock_origin_to_cf: true` (This blocks anyone trying to bypass Cloudflare and hit your VPS IP directly).

## 📝 Operating Rules
The system follows these protection layers:
1. **L4 (XDP)**: Fast drop of blacklisted IPs and malformed packets.
2. **Rate Limiting**: Per-IP and per-Fingerprint request capping.
3. **JS Challenge**: Verified browsers are allowed; automated bots are challenged.
4. **WAF (L7)**: Deep packet inspection (SQLi, XSS, Path Traversal).

## 📊 Dashboard
Access the real-time monitoring dashboard at `http://YOUR_VPS_IP:8080/dashboard`.
- **Default Port**: 8080
- **Metrics**: Cluster-wide RPS, block rates, and node health.

---
*Support: Contact hoangtuvungcao for more info.*
