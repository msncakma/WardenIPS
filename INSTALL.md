# WardenIPS - Installation and Configuration Guide

## System Requirements

| Requirement | Minimum |
|-----------|---------|
| **OS** | Ubuntu 20.04+ / Debian 11+ / CentOS 8+ |
| **Python** | 3.10+ |
| **Privileges**| root (sudo) — required for ipset and iptables |
| **RAM** | 128 MB |
| **Disk** | 50 MB (+ GeoLite2 databases ~10 MB) |

---

## 1. Install System Packages

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv ipset iptables

# CentOS / RHEL
sudo dnf install -y python3 python3-pip ipset iptables
```

---

## 2. Deploy Project Files

Copy all WardenIPS files to your server:

```bash
# Example: Deploying to /opt/wardenips
sudo mkdir -p /opt/wardenips
sudo cp -r . /opt/wardenips/
cd /opt/wardenips
```

**Final directory structure:**

```
/opt/wardenips/
├── wardenips/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── whitelist.py
│   │   ├── logger.py
│   │   ├── exceptions.py
│   │   ├── models.py
│   │   ├── asn_lookup.py
│   │   ├── ip_hasher.py
│   │   ├── database.py
│   │   ├── firewall.py
│   │   ├── abuseipdb.py
│   │   ├── updater.py
│   │   └── log_tailer.py
│   └── plugins/
│       ├── __init__.py
│       ├── base_plugin.py
│       ├── ssh_plugin.py
│       └── minecraft_plugin.py
├── config.yaml
├── requirements.txt
├── main.py
└── INSTALL.md
```

---

## 3. Python Virtual Environment (Venv) Setup

Running WardenIPS in an isolated environment is the safest method.

```bash
cd /opt/wardenips
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
deactivate
```

---

## 4. Download MaxMind GeoLite2 Databases

WardenIPS uses MaxMind GeoLite2 databases to locally resolve ASN and country information. A **free** MaxMind account is required.

### 4.1 Create a MaxMind Account

1. Go to https://www.maxmind.com/en/geolite2/signup
2. Create a free account
3. Get your license key (**Account > Manage License Keys**)

### 4.2 Download the Databases

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

# Cleanup
rm -rf /tmp/GeoLite2-*
```

> **NOTE:** Replace `YOUR_LICENSE_KEY` with your actual key.

---

## 5. config.yaml Configuration

Edit the `/opt/wardenips/config.yaml` file:

### 5.1 REQUIRED Changes

```yaml
# IP Hashing Salt Value — U MUST CHANGE THIS!
database:
  ip_hashing:
    salt: "ENTER-A-STRONG-RANDOM-VALUE-HERE"
```

To generate a salt:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5.2 Whitelist — Add Your IP

```yaml
whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "YOUR_SERVER_IP"            # <-- Add your IP!
    - "YOUR_HOME_IP"              # <-- Add your home IP!
  cidr_ranges:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

> **WARNING:** If you don't add your own IP to the whitelist, you could be locked out of the server in case of a false positive!

### 5.3 Geofencing (Optional)

To allow connections only from specific countries:

```yaml
geofencing:
  enabled: true
  mode: "allow"
  countries:
    - "US"
    - "GB"
```

### 5.4 Minecraft Log Path

Update your Minecraft server's log path:

```yaml
plugins:
  minecraft:
    enabled: true
    log_path: "/opt/minecraft/logs/latest.log"  # <-- Actual path
```

### 5.5 AbuseIPDB (Optional)

Define your AbuseIPDB API key for automatic reporting:

```yaml
abuseipdb:
  enabled: true
  api_key: "YOUR_ABUSEIPDB_API_KEY"
```

---

## 6. Create Log and Database Directories

```bash
sudo mkdir -p /var/log/wardenips
sudo mkdir -p /var/lib/wardenips
```

---

## 7. Execution

### Manual Run (Testing)

```bash
cd /opt/wardenips
sudo ./venv/bin/python main.py
```

### Systemd Service (Production)

```bash
sudo tee /etc/systemd/system/wardenips.service << 'EOF'
[Unit]
Description=WardenIPS - Autonomous Intrusion Prevention System
After=network.target

[Service]
Type=simple
ExecStart=/opt/wardenips/venv/bin/python /opt/wardenips/main.py --config /opt/wardenips/config.yaml
WorkingDirectory=/opt/wardenips
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable wardenips
sudo systemctl start wardenips

# Check the status
sudo systemctl status wardenips

# Monitor logs
sudo journalctl -u wardenips -f
```

---

## 8. Verification

```bash
# Is WardenIPS running?
sudo systemctl status wardenips

# Is the ipset set created?
sudo ipset list warden_blacklist

# Is the log file being written to?
tail -f /var/log/wardenips/warden.log

# Test: SSH brute-force simulation (FROM ANOTHER MACHINE)
ssh -o StrictHostKeyChecking=no fake_user@SERVER_IP
```

---

## Troubleshooting

| Issue | Solution |
|-------|-------|
| `Permission denied` | Run with `sudo` |
| `ipset not found` | `sudo apt install ipset` |
| `geoip2 not found` | `pip3 install geoip2` within the venv |
| ASN results empty | Check GeoLite2 .mmdb files |
| Locked out of server | Did you forget to add your IP to the Whitelist? |
| Log file not found | Check log paths in `config.yaml` |
