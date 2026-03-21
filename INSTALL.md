# WardenIPS — Installation & Configuration Guide

**Version: 0.4.0-beta-5**

Complete guide for deploying WardenIPS on a Linux server.

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| **OS** | Ubuntu 20.04+ / Debian 11+ / CentOS 8+ |
| **Python** | 3.10+ |
| **Privileges** | root (sudo) — required for ipset and iptables |
| **RAM** | 128 MB |
| **Disk** | 50 MB (+ GeoLite2 databases ~10 MB) |

---

## Quick Install (One-Line)

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

The installer handles everything: dependencies, venv, config, systemd service, and a dedicated service user.

During a fresh one-line install, the installer asks which first-setup blocklist window to use:

- `7d` (recommended): lower false-positive risk
- `14d`: broader initial coverage

For unattended installs, preseed the choice:

```bash
sudo env WARDENIPS_FIRST_SETUP_MODE=7d sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

To start immediately after install:

```bash
sudo env WARDENIPS_AUTOSTART=1 sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

Skip to [Section 5](#5-configure-configyaml) if you used the one-line installer.

---

## Manual Installation

### 1. Install System Packages

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv ipset iptables git

# CentOS / RHEL
sudo dnf install -y python3 python3-pip ipset iptables git
```

### 2. Clone and Deploy

```bash
sudo git clone https://github.com/msncakma/WardenIPS.git /opt/wardenips
cd /opt/wardenips
```

### 3. Create Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
deactivate
```

### 4. Create Runtime Directories

```bash
sudo mkdir -p /var/log/wardenips
sudo mkdir -p /var/lib/wardenips
```

---

## 5. Configure config.yaml

```bash
sudo nano /opt/wardenips/config.yaml
```

### 5.1 Whitelist Your IPs (CRITICAL)

Add your server IP, home IP, and any management IPs. If you skip this, a false positive could lock you out.

```yaml
whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "YOUR_SERVER_IP"
    - "YOUR_HOME_IP"
  cidr_ranges:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

### 5.2 Blocklist Protection

WardenIPS ships with built-in blocklist protection powered by [AbuseIPDB curated lists](https://github.com/borestad/blocklist-abuseipdb). This is **enabled by default** and provides two layers of protection:

**How it works:**

| Phase | ipset Name | Purpose |
|-------|-----------|---------|
| **First Setup** | `wardenips_first_setup` | Loads ~107K IPs (7d) or ~132K IPs (14d) on first run. Auto-removed after the chosen period to prevent stale false-positives. |
| **Active** | `wardenips_active` | Refreshed daily at your configured time with ~80K known bad IPs from the last 24 hours. Additive — IPs accumulate. |

**Configuration:**

```yaml
blocklist:
  enabled: true
  timezone: "Europe/Istanbul"     # Your local timezone
  fetch_time: "04:00"             # When to fetch the daily list (24h format)
  first_setup:
    mode: "7d"                    # "7d" (recommended) or "14d"
```

| Option | What it does |
|--------|-------------|
| `mode: "7d"` | **(Recommended)** Loads the last 7 days of worst offenders (~107K IPs). Smaller set, less chance of false positives. Cleans up after 7 days. |
| `mode: "14d"` | Loads the last 14 days (~132K IPs). Broader initial coverage but slightly higher false-positive risk. Cleans up after 14 days. |
| `timezone` | Your local timezone for scheduling. Examples: `Europe/Istanbul`, `America/New_York`, `Asia/Tokyo`, `UTC`. |
| `fetch_time` | Daily fetch time in your timezone. `"04:00"` = 4 AM local time. Low-traffic hours recommended. |

The `installed_at` and `completed` fields are managed automatically — do not edit them.

**Data source:** Lists are sourced from [`borestad/blocklist-abuseipdb`](https://github.com/borestad/blocklist-abuseipdb) — ~100% confidence AbuseIPDB offenders, updated multiple times per day.

### 5.4 Dashboard

```yaml
dashboard:
  enabled: true
  host: "127.0.0.1"     # Use 0.0.0.0 for remote access
  port: 7680
```

After first start, navigate to `http://HOST:7680/setup` to create your admin account.

| Route | Access |
|-------|--------|
| `/dashboard` | Public read-only overview |
| `/admin` | Login-protected admin console |
| `/setup` | First-boot admin account creation |

### 5.5 Plugin Configuration

Enable the plugins you need:

```yaml
plugins:
  ssh:
    enabled: true
    log_path: "/var/log/auth.log"

  minecraft:
    enabled: false
    log_path: "/opt/minecraft/logs/latest.log"

  nginx:
    enabled: false
    log_path: "/var/log/nginx/access.log"
```

### 5.6 Geofencing (Optional)

Allow connections only from specific countries:

```yaml
geofencing:
  enabled: true
  mode: "allow"
  countries:
    - "TR"
    - "US"
```

### 5.7 AbuseIPDB Reporting (Optional)

Automatically report banned IPs to AbuseIPDB:

```yaml
abuseipdb:
  enabled: true
  api_key: "YOUR_ABUSEIPDB_API_KEY"
```

### 5.8 Notifications (Optional)

```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"

  discord:
    enabled: true
    webhook_url: "YOUR_WEBHOOK_URL"
```

---

## 6. Download MaxMind GeoLite2 Databases

WardenIPS uses MaxMind GeoLite2 for ASN and country lookups. A **free** MaxMind account is required.

1. Sign up at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)
2. Get your license key from **Account > Manage License Keys**
3. Download:

```bash
sudo mkdir -p /var/lib/wardenips

# GeoLite2-ASN
wget -O /tmp/GeoLite2-ASN.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"
tar -xzf /tmp/GeoLite2-ASN.tar.gz -C /tmp/
sudo cp /tmp/GeoLite2-ASN_*/GeoLite2-ASN.mmdb /var/lib/wardenips/

# GeoLite2-Country
wget -O /tmp/GeoLite2-Country.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"
tar -xzf /tmp/GeoLite2-Country.tar.gz -C /tmp/
sudo cp /tmp/GeoLite2-Country_*/GeoLite2-Country.mmdb /var/lib/wardenips/

rm -rf /tmp/GeoLite2-*
```

Replace `YOUR_LICENSE_KEY` with your actual key.

---

## 7. Start WardenIPS

### Manual Run (Testing)

```bash
cd /opt/wardenips
sudo ./venv/bin/python main.py
```

### Systemd Service (Production)

```bash
sudo systemctl daemon-reload
sudo systemctl enable wardenips
sudo systemctl start wardenips
```

Monitor:

```bash
sudo systemctl status wardenips
sudo journalctl -u wardenips -f
```

If your Velocity/Minecraft logs are under `/home/...`, WardenIPS now applies `ProtectHome=read-only` automatically.

The installer also auto-adds read-only access for `/home`-based Minecraft and Velocity log directories based on configured `log_path` values.

After changing log paths, re-run installer (update mode) and restart service.

### Docker

```bash
docker compose up -d --build
docker compose logs -f wardenips
```

---

## 8. Post-Install Verification

```bash
# Service running?
sudo systemctl status wardenips

# ipset sets created?
sudo ipset list warden_blacklist -t
sudo ipset list wardenips_first_setup -t    # Blocklist first-setup
sudo ipset list wardenips_active -t          # Blocklist active

# Log output?
tail -f /var/log/wardenips/warden.log
```

---

## 9. CLI Commands

After install, the `wardenips` wrapper is available system-wide:

```bash
wardenips version
wardenips status
wardenips service-status
wardenips logs
wardenips shell
```

---

## Uninstall

```bash
sudo sh uninstall.sh          # Keep config and data
sudo sh uninstall.sh --purge  # Remove everything
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Permission denied` | Run with `sudo` |
| `ipset not found` | `sudo apt install ipset` |
| `geoip2 not found` | Activate venv first: `source venv/bin/activate && pip install geoip2` |
| ASN results are empty | Check GeoLite2 `.mmdb` files exist in `/var/lib/wardenips/` |
| Locked out of server | Your IP is missing from `whitelist.ips` in config.yaml |
| Log file not found | Verify `log_path` values in the plugins section |
| Dashboard shows HTTPS error | Dashboard is plain HTTP by default. Use `http://`, not `https://` |
| Blocklist not loading | Check network connectivity and that `blocklist.enabled` is `true` |
| Log path under `/home` unreadable | Re-run installer after updating plugin `log_path`; verify `systemctl cat wardenips` includes `ProtectHome=read-only` and matching `ReadOnlyPaths` |
