# WardenIPS

WardenIPS is an asynchronous intrusion prevention system for Linux servers. It analyzes service logs in real time, scores suspicious activity, and enforces temporary or permanent blocks using ipset and iptables.

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/msncakma)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Transparency and Current Status

This project is active and evolving quickly. Please read this before production deployment:

- Current development state: pre-release, with major recent feature additions.
- Stability expectation: suitable for labs, staging, and controlled production pilots.
- Testing status: core flows are implemented, but broad end-to-end regression coverage is still in progress.
- Operational risk: false positives and lockout risk are possible if whitelist and thresholds are not configured carefully.
- Recommendation: start in a non-critical environment, monitor logs, then tune before full rollout.

## Core Capabilities

- High-performance async pipeline using asyncio-based components.
- IPv4 and IPv6 firewall enforcement with ipset plus iptables and ip6tables.
- Privacy-aware storage using salted, hashed IP representation.
- Local ASN and country intelligence via MaxMind GeoLite2 databases.
- Plugin architecture for protocol-specific detection logic.
- Built-in plugins: SSH, Minecraft, and Nginx access/error log analysis.
- Burst and flood detection for fast automated containment.
- Optional AbuseIPDB reporting.
- Optional Telegram and Discord notifications.
- Optional Redis backend for multi-node and higher-throughput deployments.
- Optional decentralized threat intelligence peer synchronization.
- Optional web dashboard with live metrics and active event views.
- Systemd service support, Docker support, and one-command installer script.

## Architecture Snapshot

- Collectors tail log files from enabled plugins.
- Parsers convert raw lines into structured security events.
- Scoring logic computes risk and threat level per event.
- Firewall manager applies bans when thresholds are reached.
- Persistence layer stores event and ban history in SQLite or Redis.
- API and dashboard expose operational visibility in real time.

For deeper implementation details, see [WARDEN_ARCHITECTURE.md](WARDEN_ARCHITECTURE.md).

## Requirements

- Linux host with root privileges.
- Python 3.10 or newer.
- ipset and iptables installed.
- Optional ip6tables for IPv6 enforcement.
- Optional MaxMind GeoLite2 ASN and Country databases.

Detailed setup instructions: [INSTALL.md](INSTALL.md)

## Quick Start

### Option A: Automated Install

```bash
sudo bash install.sh
sudo nano /opt/wardenips/config.yaml
sudo systemctl start wardenips
sudo systemctl status wardenips
```

### Option B: Manual Install

```bash
sudo apt update
sudo apt install -y python3 python3-venv ipset iptables git
git clone https://github.com/msncakma/WardenIPS.git
cd WardenIPS
python3 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
sudo nano config.yaml
sudo ./venv/bin/python main.py
```

## Minimum Safe Configuration Checklist

Before first run, verify the following in config.yaml:

- Replace the default IP hashing salt with a strong random value.
- Add your server, home, and management IPs to whitelist.ips.
- Validate plugin log paths for your environment.
- Confirm ban thresholds and durations match your risk tolerance.
- Keep dashboard API key empty until you explicitly need API-level auth.

## Dashboard

When enabled, the dashboard serves a live UI and API.

- Default URL: http://127.0.0.1:7680/
- Refresh model: live polling.
- API routes include health, stats, bans, events, timeline, plugin stats, and threat distribution.

If the service runs on a remote server, access via SSH tunnel or publish the port intentionally behind a reverse proxy.

## Operations

### Service Management

```bash
sudo systemctl start wardenips
sudo systemctl stop wardenips
sudo systemctl restart wardenips
sudo systemctl status wardenips
sudo journalctl -u wardenips -f
```

### CLI Status

```bash
python3 main.py --status
```

### Docker

```bash
docker compose up -d --build
docker compose logs -f wardenips
```

## Release and Versioning Policy

Project tags follow this maturity model:

- SNAPSHOT: latest development changes, unstable by definition.
- ALPHA: early feature testing phase.
- BETA: feature complete with active bug fixing.
- RELEASE: production-oriented, validated stable baseline.

Until a formal RELEASE tag is published for a given change set, treat it as non-final.

## Security and Risk Notes

- WardenIPS modifies host firewall state and can disrupt legitimate access if misconfigured.
- Always keep out-of-band console access available during first deployment.
- Always validate whitelist entries before enabling autonomous bans.
- Always test geofencing and aggressive thresholds in staging first.

## Contributing and Support

- Bug reports and feature requests: open a GitHub issue with logs and reproduction steps.
- Pull requests are welcome for fixes, tests, performance, and plugin improvements.
- If this project helps you, support development on Ko-fi: [ko-fi.com/msncakma](https://ko-fi.com/msncakma)

## License

This project is licensed under MIT. See [LICENSE](LICENSE).