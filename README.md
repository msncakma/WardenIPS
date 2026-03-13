# WardenIPS

WardenIPS is a Linux-native, asynchronous intrusion prevention platform that watches real service logs, scores suspicious behavior, and blocks attackers at the firewall layer before they become a bigger problem.

It is built for operators who want something lighter than a SIEM, faster than manual log review, and more modern than static fail2ban-style rules.

Maintainer: `msncakma`

If you want a cleaner product-style overview for sharing or presentation, see [docs/index.md](docs/index.md).

[![Version](https://img.shields.io/badge/version-0.2.6--beta.1-green.svg)](https://github.com/msncakma/WardenIPS)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/msncakma)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why WardenIPS

- Real-time prevention, not just log collection.
- Linux-native enforcement with ipset, iptables, and IPv6 support.
- Built-in blocklist protection powered by AbuseIPDB curated threat data.
- ASN-based threat detection with autonomous weekly GeoLite2 updates.
- Live operational dashboard with continuously updating metrics and event visibility.
- Privacy-aware design: no sensitive IP hashing, direct ASN enrichment.
- Plugin-based detection model for Portscans, SSH, Minecraft, and Nginx workloads.
- Burst and flood detection for fast bot and scanner containment.
- Optional Telegram, Discord, AbuseIPDB, Redis, and Docker integrations.

## Transparency

WardenIPS v0.3.0-beta-4 is feature-complete for its intended scope, with professional CLI tooling and robust error handling.

- Current state: **v0.3.0-beta-4** — active beta line with Debian-only packaging and release pipeline.
- Testing state: core flows are implemented and functional, broad production validation is ongoing.
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
- Advanced admin console available at `/admin` with live filters, raw active firewall IP view, operator advice, and blocklist protection status.

### Blocklist Protection (v0.2.0+)

WardenIPS ships with built-in blocklist protection powered by [AbuseIPDB curated lists](https://github.com/borestad/blocklist-abuseipdb).

- **First Setup phase**: On first run, loads ~107K (7d) or ~132K (14d) known malicious IPs into a dedicated ipset. This set auto-expires after the chosen period to prevent stale false-positives.
- **Daily Active refresh**: Every day at a configurable time, fetches ~80K IPs reported in the last 24 hours. These accumulate in a separate active ipset.
- All lists are 100% confidence AbuseIPDB offenders, updated multiple times per day.
- Timezone-aware scheduling — set your local timezone and preferred fetch time.
- Zero configuration required — enabled by default with sensible defaults.

### ASN-Based Threat Detection (New in v0.2.3)

WardenIPS now includes autonomous ASN enrichment and configurable ASN-based blocking.

- **Automatic GeoLite2 updates**: Downloads and refreshes [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) weekly (Thursday 03:00 UTC) at zero overhead.
- **Suspicious ASN list**: Configure custom ASN numbers (e.g., datacenter providers) to automatically flag and optionally block traffic from those networks.
- **Risk integration**: ASN-flagged connections receive a +20 point risk boost in scoring pipeline.
- **No manual updates required**: Uses GitHub CDN for reliable, free, and transparent threat data.
- **Dashboard badge**: Real-time display of suspicious ASN events with operator indicators.

### Layered Detection

- Portscan and botnet detection with UFW integration and standalone `iptables` trap rules (instant ban for honeypot ports).
- SSH brute-force detection.
- Minecraft rapid connection and bot-style behavior detection.
- Nginx web threat detection for scanners, suspicious paths, traversal probes, and SQLi-style traffic.
- ASN enrichment with autonomous GeoLite2 updates (Loyalsoldier/geoip).
- Configurable ASN blocking for datacenter and suspicious networks.

### Operator-Friendly Deployment

- Systemd service support.
- Docker deployment option.
- SQLite by default, Redis for scaled or clustered deployments.
- One-line bootstrap installer.

## One-Line Install

For Debian/Ubuntu-style systems:

```sh
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

What the Installer Does:

- Installs required system dependencies (curl, git, ipset, iptables, etc.).
- Fetches or updates the project files from the repository.
- Creates and repairs the Python virtual environment if needed.
- Installs Python dependencies from `requirements.txt`.
- Creates a dedicated `wardenips` service user and prepares runtime ownership automatically.
- Preserves the previous `config.yaml`, then merges any newly added template keys automatically.
- Downloads initial GeoLite2-ASN.mmdb from Loyalsoldier/geoip for ASN lookups.
- Grants the service account read access to system logs (SSH, Nginx, etc.).
- Enables the dashboard by default on `127.0.0.1:7680`.
- Installs and enables the systemd service.
- Installs a professional, colorized `wardenips` CLI command wrapper with integrated help.
- Traps errors with line numbers for easier troubleshooting.

Dashboard auth notes:

- The built-in dashboard serves plain HTTP by default, so open it as `http://HOST:PORT`, not `https://HOST:PORT`, unless you put it behind a TLS reverse proxy.
- `/dashboard` is the public read-only dashboard route.
- `/admin` is the canonical admin console route.
- Fresh installs now require the first-boot `/setup` flow before `/admin` becomes available.
- `/` follows `dashboard.homepage` and defaults to the public dashboard.
- Set `dashboard.public_dashboard: true` to let guests view the overview without logging in.
- The first managed admin account is stored in the selected backend and uses Argon2 password hashing plus TOTP verification.
- `dashboard.api_key` is supported for scripted API clients using Bearer authentication.
- Login attempts are rate-limited server-side.
- Admin sessions expire after 10 minutes of inactivity by default.
- High-risk admin actions are written to the audit log backend.

What it deliberately does not do automatically:

- It does not assume your whitelist is correct.
- It does not force an immediate production start unless you explicitly choose to.

Bootstrap Installer Flags:

- `WARDENIPS_AUTOSTART=1` starts the service automatically after install.
- `WARDENIPS_ENABLE_DASHBOARD=0` keeps the dashboard disabled during bootstrap.
- `WARDENIPS_REPO_BRANCH=branch-name` installs from a different branch.
- `WARDENIPS_USER=username` overrides the default service user.
- `WARDENIPS_GROUP=groupname` overrides the default service group.
- `WARDENIPS_VERBOSE=1` shows detailed installation output.
- `WARDENIPS_DEBUG=1` enables debug tracing (set -x).

Verbose and debug install commands:

```sh
sudo env WARDENIPS_VERBOSE=1 sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
sudo env WARDENIPS_DEBUG=1 sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

CLI Wrapper Commands (v0.2.3+):

**Core Operations:**
```sh
wardenips start          # Start the WardenIPS service
wardenips stop           # Stop the WardenIPS service  
wardenips restart        # Restart the WardenIPS service
```

**Monitoring & Status:**
```sh
wardenips status         # Show systemd service status
wardenips logs           # Stream live service logs (journalctl -f)
wardenips summary        # Display database statistics and event counts
```

**Configuration:**
```sh
wardenips config         # Print configuration file path
wardenips path           # Print installation directory
wardenips edit           # Edit configuration with default editor (sudo)
```

**Utilities:**
```sh
wardenips version        # Show WardenIPS version
wardenips help           # Show help with colored command categories
```

All commands use `sudo` automatically when elevated access is required. The CLI wrapper includes a professional ANSI-colored banner with command categories and error trapping for better diagnostics.

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

- Add your server, home, VPN, and management IPs to `whitelist.ips`.
- Validate the log paths for enabled plugins.
- Review `firewall.ban_threshold` and ban duration settings.
- Keep out-of-band access available during first deployment.

## Core Capabilities

- Async event pipeline built for low overhead.
- IPv4 and IPv6 ban enforcement.
- Blocklist protection with AbuseIPDB curated threat data.
- Source IP based event and ban correlation.
- SQLite or Redis backend.
- AbuseIPDB reporting.
- Telegram and Discord notifications.
- Dashboard API and web UI.
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

### Dashboard Routes

```text
/     -> dashboard v1
/admin -> advanced admin dashboard
/v2    -> legacy redirect to /admin
```

### Docker

```bash
docker compose up -d --build
docker compose logs -f wardenips
```

### Uninstall

```bash
sudo sh uninstall.sh
```

Full removal including config, logs, and database:

```bash
sudo sh uninstall.sh --purge
```

## Release Policy

WardenIPS uses a staged maturity model:

- SNAPSHOT: newest development line, unstable by definition.
- ALPHA: early feature validation.
- BETA: feature complete with active stabilization.
- RELEASE: production-oriented stable milestone.

Current version: **v0.3.0-beta-4**

Until a formal RELEASE tag exists for a given build, treat that build as non-final.

### What changed in v0.2.2

- **Blocklist Protection**: Replaced the experimental P2P threat mesh with a streamlined blocklist system powered by [AbuseIPDB curated lists](https://github.com/borestad/blocklist-abuseipdb). Two-phase protection: first-setup bulk load + daily active refresh.
- **Timezone-aware scheduling**: Blocklist fetch runs at a configurable local time instead of a fixed UTC offset.
- **Dashboard updates**: Blocklist status, first-setup progress, and active IP counts are now visible in both the public and admin dashboards.
- **Simplified architecture**: Removed P2P node synchronization, hash-based threat sharing, and mesh topology code. The codebase is leaner and easier to maintain.

## Security Notes

- WardenIPS changes host firewall state.
- Misconfiguration can block legitimate traffic.
- Aggressive tuning should always be introduced gradually.
- Blocklist data is sourced from curated, high-confidence AbuseIPDB lists — not raw community feeds.

## Who This Is For

- VPS and bare-metal operators.
- Indie game server admins.
- Small SaaS teams.
- Self-hosters who want live protection without enterprise overhead.

## Contributing and Support

- Open issues with logs, reproduction steps, and environment details.
- Pull requests are welcome for fixes, tests, performance work, and new plugins.
- If WardenIPS helps you, support the project on Ko-fi: [ko-fi.com/msncakma](https://ko-fi.com/msncakma)

## License

This project is licensed under MIT. See [LICENSE](LICENSE).