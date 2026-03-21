# WardenIPS

WardenIPS is a Linux-native intrusion prevention platform focused on one practical outcome: detect hostile behavior quickly and enforce blocks at the firewall layer with minimal operator friction.

It is designed for teams that want stronger protection than static log-based banning, without the operational weight of a full SIEM stack.

Maintainer: msncakma

[![Version](https://img.shields.io/badge/version-0.4.0-beta--7-green.svg)](https://github.com/msncakma/WardenIPS)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/msncakma)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why Use WardenIPS

Most operators ask one simple question before adopting security tooling: Why should I run this instead of what I already have?

WardenIPS exists to answer that with clear, operational value:

- Real-time containment. It does not stop at alerting. It can apply firewall blocks when risk crosses your threshold.
- Behavioral scoring. It evaluates event patterns over time, not only single regex hits.
- Low-complexity operations. One service, one config, one dashboard, with systemd- and Docker-friendly workflows.
- Better context during incidents. You get recent events, active database bans, live firewall entries, ASN data, and operator-oriented hints in one place.
- Safe rollout model. Simulation mode lets you observe exactly what would be blocked before enforcement is enabled.

If you run internet-facing services and want practical prevention with transparent behavior, WardenIPS is the right fit.

## Transparent Status

Current version: v0.4.0-beta-7

This project is in beta, and that matters.

- Feature state: Core capabilities are in place and actively used.
- Stability state: Good for labs, staging, and controlled production pilots.
- Remaining risk: Threshold tuning, whitelist quality, and environment-specific traffic patterns still determine final safety.
- Honest recommendation: Deploy in simulation first, validate behavior, then enable enforcement.

WardenIPS is intentionally transparent about maturity. If you require a formally declared production-stable line, wait for a RELEASE tag.

## What It Does

WardenIPS continuously ingests service logs, converts them into structured security events, computes risk, and applies actions based on policy.

### Detection and Scoring

- SSH brute-force and suspicious login behavior
- Nginx probing, traversal, and injection-like patterns
- Portscan telemetry and trap-port signals
- Minecraft bot-like connection bursts
- Multi-vector scoring across plugins and time windows

### Enforcement

- Linux ipset plus iptables enforcement
- IPv4 and IPv6 support
- Permanent or timed bans
- One-way DB to firewall reconciliation from admin actions
- Simulation mode for no-risk policy validation

### Intelligence and Enrichment

- AbuseIPDB-based blocklist ingestion (first-setup and daily refresh phases)
- ASN enrichment via local GeoLite2 database
- Optional suspicious ASN weighting in risk scoring

### Visibility and Operations

- Public overview dashboard and authenticated admin console
- Live event stream, active DB bans, active firewall entries
- Query tools for IP, ASN, and username records
- Audit logging for sensitive admin actions

## What It Does Not Do

WardenIPS is powerful, but it is not magic. It deliberately does not claim the following:

- It does not replace full EDR, SIEM, or forensic platforms.
- It does not guarantee zero false positives.
- It does not auto-know which IPs are business-critical for your environment.
- It does not make careless thresholding safe.

Security outcomes still depend on good policy, sane defaults, and staged rollout.

## Architecture at a Glance

1. Tailers read service logs.
2. Plugins parse raw lines into normalized events.
3. Risk scoring evaluates severity with context.
4. Policy layer selects action (watch or ban).
5. Firewall manager applies enforcement.
6. Database stores event and ban history.
7. Dashboard and API expose current operational state.

For deeper technical detail, see [WARDEN_ARCHITECTURE.md](WARDEN_ARCHITECTURE.md).

## Installation

### Fast Install (Debian/Ubuntu style)

```sh
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

### Manual Install

```sh
sudo apt update
sudo apt install -y python3 python3-venv ipset iptables git
git clone https://github.com/msncakma/WardenIPS.git
cd WardenIPS
python3 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
sudo nano config.yaml
sudo ./venv/bin/python main.py
```

Detailed instructions: [INSTALL.md](INSTALL.md)

## First Deployment Checklist

Before enabling enforcement in production:

1. Add trusted management and admin source ranges to whitelist settings.
2. Confirm plugin log paths are correct for your distro and services.
3. Start in simulation mode and review generated actions.
4. Tune ban threshold and durations to your real traffic profile.
5. Keep out-of-band access available during first live rollout.

## Dashboard and Authentication

- Public view: /dashboard
- Admin console: /admin
- First boot setup flow: /setup
- API bearer token support for automation clients
- Session timeout and login rate limiting
- Optional per-admin TOTP requirement

Important: The built-in dashboard is plain HTTP by default. Put it behind TLS if exposed externally.

## Operational Commands

### Service Control

```sh
sudo systemctl start wardenips
sudo systemctl stop wardenips
sudo systemctl restart wardenips
sudo systemctl status wardenips
sudo journalctl -u wardenips -f
```

### Runtime Status

```sh
python3 main.py --status
```

### Docker

```sh
docker compose up -d --build
docker compose logs -f wardenips
```

### Uninstall

```sh
sudo sh uninstall.sh
```

Full cleanup:

```sh
sudo sh uninstall.sh --purge
```

## Release Model

WardenIPS follows a staged maturity policy:

- SNAPSHOT: active development, unstable by definition
- ALPHA: early feature validation
- BETA: feature complete with stabilization in progress
- RELEASE: production-oriented stable milestone

Current line is beta. Treat it as non-final until a RELEASE tag is published.

## Security and Privacy Notes

- WardenIPS modifies host firewall state.
- Bad whitelisting or aggressive policy can block legitimate users.
- ASN enrichment is local database lookup, not per-event external API calls.
- Blocklist feeds are curated external intelligence and should be treated as one signal, not absolute truth.

## Who This Is For

- VPS and bare-metal operators
- Game server administrators
- Small SaaS teams running Linux edge services
- Self-hosters who want practical prevention without heavy infrastructure

## Contributing and Support

- File issues with logs, environment details, and reproduction steps.
- Pull requests are welcome for fixes, tests, and plugin improvements.
- Support the project: [Ko-fi](https://ko-fi.com/msncakma)

## License

MIT. See [LICENSE](LICENSE).