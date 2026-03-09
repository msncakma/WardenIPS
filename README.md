# WardenIPS

WardenIPS is an autonomous, high-performance Intrusion Prevention System (IPS) for Linux-based servers. It detects botnets, DDoS attacks, and brute-force attempts in real-time and dynamically blocks them using `ipset`.

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/msncakma)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features
- **Async & Fast:** Built entirely on Python's `asyncio` and `aiofiles`.
- **ipset Backend:** O(1) IP blocking performance; capable of handling thousands of blocked IPs without server strain.
- **KVKK / GDPR Compliant:** IP addresses are securely anonymized using HMAC+SHA-256 before being stored in the SQLite database.
- **Local ASN & Geofencing:** Utilizes MaxMind GeoLite2 databases to determine if an IP belongs to a datacenter or a blocked country.
- **Plugin System:** Easily extendable! Currently supports SSH brute-force and Minecraft botnet detection.
- **AbuseIPDB Integration:** Automatically reports malicious IPs to AbuseIPDB.
- **Auto-Update Checker:** Alerts you in the console when a new release is available.

## Installation

A detailed installation guide is available in [INSTALL.md](INSTALL.md). 

### Quick Start (Production)
```bash
sudo apt update
sudo apt install -y python3 python3-venv ipset iptables git
git clone https://github.com/msncakma/WardenIPS wardenips
cd wardenips
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Edit config.yaml to add your server/home IPs to the whitelist and change the IP hashing salt!
sudo nano config.yaml

# Run the system
sudo ./venv/bin/python main.py
```

## Need Help? Found a Bug?
If you encounter any issues, need assistance, or have a feature request, please **open an Issue** on this GitHub repository. Provide as much detail as possible (logs, steps to reproduce) so we can help you promptly.

## Support the Developer
If you find WardenIPS useful and want to support its continuous development, consider buying me a coffee:
👉 **[Support me on Ko-fi: msncakma](https://ko-fi.com/msncakma)**

---

## 🚀 Versioning Structure Explained

WardenIPS uses a structured release cycle to ensure stability while providing early access to new features. 
Our repository releases follow these tags:
- **`SNAPSHOT`**: Daily or experimental builds. These contain the newest code but might be unstable. Not recommended for production.
- **`ALPHA`**: Early testing phases of major new features. Suitable for testing environments.
- **`BETA`**: Feature-complete builds undergoing final bug fixing. Stable enough for brave production users.
- **`RELEASE` (Stable)**: Heavily tested, production-ready builds. Use these tags (e.g., `v1.0.0`) for your mission-critical servers.

---

## 🛠️ TODO / Future Road map
WardenIPS is an actively evolving project. Here are some of our planned features:
- [x] `Add systemd service template (wardenips.service) for daemonizing.`
- [x] `Support for IPv6 blocking.`
- [x] `Implement Docker support for easier deployment.`
- [x] `Add Nginx / Apache plugin for Layer 7 web threat detection.`
- [x] `Implement Redis backend support as an alternative to SQLite for enterprise clusters.`
- [x] `Add Web Dashboard (UI) for monitoring blocked IPs and risk scores.`
- [x] `Add Telegram and Discord integration for notifications.`
- [x] `Auto setup script.`
- [x] `Decentralized Threat Intelligence:` A feature that can be toggled on/off to sync banned IPs between all WardenIPS instances globally automatically!
- [x] `Burst/Flood auto-detection:` Automatically bans IPs that send a flood of events within a short time window.
- [x] `CLI status command:` `python3 main.py --status` for quick database summary without starting the daemon.
- [x] `Periodic runtime statistics logging:` Automatic uptime/event/ban summaries every 5 minutes.

---

**Disclaimer:** WardenIPS is provided "as is". Please ensure you whitelist your own IPs before deploying to avoid locking yourself out of your server.

<p align="center">Made with ❤️ for server administrators by msncakma and AIs :D.</p>