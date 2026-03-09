# WardenIPS

## Autonomous defense for Linux servers

WardenIPS is a real-time intrusion prevention platform that reads production logs, scores suspicious activity, and enforces bans directly at the firewall layer.

It is designed for teams that want fast feedback, practical automation, and a cleaner operational experience than piecing together multiple security tools.

## What makes it compelling

- Real-time detection and enforcement.
- Linux-native firewall blocking with IPv4 and IPv6 support.
- Live dashboard with active bans, event flow, threat breakdowns, and attacker concentration.
- Privacy-aware design with salted IP hashing.
- Plugin-driven model for SSH, Minecraft, and Nginx workloads.
- Threat mesh for cross-node awareness using hash-based intelligence exchange.
- Straightforward deployment through systemd, Docker, or one-line bootstrap install.

## Product direction

WardenIPS is not trying to be a bloated SIEM replacement. The goal is a fast, opinionated defensive layer that is easy to deploy, operationally visible, and extensible.

The long-term vision is simple:

- Detect threats faster.
- Block earlier.
- Correlate across multiple nodes.
- Keep the operator in control.

## Transparent maturity statement

WardenIPS is under active development.

- Major features are implemented.
- The product is promising and already useful.
- Broader production hardening and validation are still ongoing.
- Early adopters should treat current builds as pre-release unless explicitly tagged as RELEASE.

That is a feature, not a disclaimer hidden in small print: you can adopt early, see the roadmap clearly, and shape the product while it is still moving fast.

## Deployment experience

### One-line install

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)"
```

### What happens next

- Dependencies are installed.
- Project files are deployed.
- The Python environment is prepared automatically.
- A secure hashing salt is generated.
- The dashboard is enabled by default.
- A systemd service is installed.

## Threat Mesh

Threat Mesh is one of the most interesting parts of WardenIPS.

Multiple nodes can share hashed active-ban indicators with each other over HTTP. That means a fleet can build collective awareness without shipping raw source IPs around the network.

Current mode is intentionally conservative:

- Shared intelligence is correlation-oriented.
- Plaintext IPs are not exchanged.
- Peer data improves visibility and future decision-making.

This is the right design tradeoff for an early secure implementation.

## Built for people running real services

- VPS and dedicated server operators.
- Game server administrators.
- Self-hosters.
- Small SaaS teams.
- Security-conscious builders who want practical control without enterprise sprawl.

## Support

If WardenIPS is useful to you and you want to support its development, you can support the project here:

- [Ko-fi](https://ko-fi.com/msncakma)

Main repository: [README.md](../README.md)