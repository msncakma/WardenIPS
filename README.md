# WardenIPS

WardenIPS is a Linux-native, asynchronous intrusion prevention platform that watches real service logs, scores suspicious behavior, and blocks attackers at the firewall layer before they become a bigger problem.

It is built for operators who want something lighter than a SIEM, faster than manual log review, and more modern than static fail2ban-style rules.

If you want a cleaner product-style overview for sharing or presentation, see [docs/index.md](docs/index.md).

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/msncakma)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why WardenIPS

- Real-time prevention, not just log collection.
- Linux-native enforcement with ipset, iptables, and IPv6 support.
- Live operational dashboard with continuously updating metrics and event visibility.
- Privacy-aware design: sensitive IP data is stored as salted hashes.
- Plugin-based detection model for SSH, Minecraft, and Nginx workloads.
- Burst and flood detection for fast bot and scanner containment.
- Optional Telegram, Discord, AbuseIPDB, Redis, Docker, and peer intelligence features.

## Transparency

WardenIPS is promising, but it is not pretending to be more mature than it is.

- Current state: active pre-release development.
- Testing state: major flows are implemented, but broad production validation is still ongoing.
- Deployment advice: use in labs, staging, or controlled production pilots first.
- Operational reality: misconfigured whitelists or aggressive thresholds can still block legitimate traffic.
- Recommendation: deploy carefully, observe behavior, then tighten policy.

If you need a fully battle-tested stable line today, wait for a formal RELEASE tag. If you want early access and influence over the direction of the product, this is the right phase.

## Standout Features

### Live Dashboard

WardenIPS ships with a built-in web dashboard for real-time visibility.

- Live auto-refreshing UI.
- Active bans, recent events, risk levels, countries, plugins, and attacker concentration.
- Fast operational feedback without external observability tooling.

### Privacy-Preserving Threat Mesh

WardenIPS includes decentralized threat intelligence synchronization between nodes.

- Nodes share ban indicators with peers over HTTP.
- Shared data is hash-based, so plaintext IPs do not leave the node.
- This currently works as correlation and awareness across nodes.
- It is valuable for multi-server fleets, clusters, and distributed service edges.

Transparent note: the current threat intel feed is hash-only, so it improves visibility and correlation but does not directly reconstruct remote IPs for firewall blocking.

### Layered Detection

- SSH brute-force detection.
- Minecraft rapid connection and bot-style behavior detection.
- Nginx web threat detection for scanners, suspicious paths, traversal probes, and SQLi-style traffic.
- ASN and country enrichment with MaxMind GeoLite2.
- Geofencing and datacenter-aware risk escalation.

### Operator-Friendly Deployment

- Systemd service support.
- Docker deployment option.
- SQLite by default, Redis for scaled or clustered deployments.
- One-line bootstrap installer.

## One-Line Install

For Debian/Ubuntu-style systems:

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

What the installer does:

- Installs required system dependencies.
- Fetches or updates the project files.
- Creates and repairs the Python virtual environment if needed.
- Installs Python dependencies.
- Generates a secure hashing salt automatically.
- Enables the dashboard by default on `127.0.0.1:7680`.
- Installs and enables the systemd service.

What it deliberately does not do automatically:

- It does not assume your whitelist is correct.
- It does not force an immediate production start unless you explicitly choose to.

Bootstrap installer flags:

- `WARDENIPS_AUTOSTART=1` starts the service automatically after install.
- `WARDENIPS_ENABLE_DASHBOARD=0` keeps the dashboard disabled during bootstrap.
- `WARDENIPS_REPO_BRANCH=branch-name` installs from a different branch.

## Quick Start

### Automated Install

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
sudo nano /opt/wardenips/config.yaml
sudo systemctl start wardenips
sudo systemctl status wardenips
```

### Manual Install

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

Detailed setup instructions: [INSTALL.md](INSTALL.md)

## First-Run Safety Checklist

Before enabling autonomous enforcement in a real environment:

- Replace or verify the generated IP hashing salt.
- Add your server, home, VPN, and management IPs to `whitelist.ips`.
- Validate the log paths for enabled plugins.
- Review `firewall.ban_threshold` and ban duration settings.
- Keep out-of-band access available during first deployment.

## Core Capabilities

- Async event pipeline built for low overhead.
- IPv4 and IPv6 ban enforcement.
- Salted IP hashing for privacy-aware storage.
- SQLite or Redis backend.
- AbuseIPDB reporting.
- Telegram and Discord notifications.
- Dashboard API and web UI.
- Threat-intel peer sync.
- Docker and systemd support.

## Architecture

- Log tailers ingest service output.
- Plugins parse raw events into structured security signals.
- Risk scoring determines severity and enforcement.
- Firewall manager applies bans.
- Database layer stores event and ban history.
- Dashboard and APIs expose live operational state.

For deeper design details, see [WARDEN_ARCHITECTURE.md](WARDEN_ARCHITECTURE.md).

## Operational Commands

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

## Release Policy

WardenIPS uses a staged maturity model:

- SNAPSHOT: newest development line, unstable by definition.
- ALPHA: early feature validation.
- BETA: feature complete with active stabilization.
- RELEASE: production-oriented stable milestone.

Until a formal RELEASE tag exists for a given build, treat that build as non-final.

## Security Notes

- WardenIPS changes host firewall state.
- Misconfiguration can block legitimate traffic.
- Aggressive tuning should always be introduced gradually.
- Threat intel is currently correlation-focused, not blind remote-ban automation.

## Who This Is For

- VPS and bare-metal operators.
- Indie game server admins.
- Small SaaS teams.
- Self-hosters who want live protection without enterprise overhead.
- Teams building early distributed defense workflows across multiple nodes.

## Contributing and Support

- Open issues with logs, reproduction steps, and environment details.
- Pull requests are welcome for fixes, tests, performance work, and new plugins.
- If WardenIPS helps you, support the project on Ko-fi: [ko-fi.com/msncakma](https://ko-fi.com/msncakma)

## License

This project is licensed under MIT. See [LICENSE](LICENSE).