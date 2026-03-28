# WardenIPS Release Notes

## v1.0.0 - Major Platform Update

Release date: 2026-03-28

This release marks the first stable major line for WardenIPS and consolidates a broad set of architectural, operational, and dashboard improvements completed across recent phases.

### Highlights

- Stable major version baseline: `1.0.0`
- Dashboard backend modernization with modularized route/service structure
- New professional CLI architecture (`wardenips-cli`) with direct and API client modes
- Service-layer refactor for ban, auth, whitelist, config, firewall, permission, and audit domains
- Operational enhancements including hot-reload foundations and improved admin workflows
- Frontend modernization assets wired into dashboard delivery path

### API and Backend

- Expanded modular API routes under dedicated route modules
- Service-oriented backend split that reduces monolithic handler pressure
- Better separation of concerns between HTTP handlers and business logic
- WebSocket and asset integration paths in dashboard backend
- Hardened asset serving constraints for safer static file access

### CLI and Operations

- Structured command architecture under `wardenips/cli/`
- Client abstraction with direct and API transport layers
- Ban, whitelist, firewall, config, and database command scaffolding
- Improved operational ergonomics and output consistency

### Dashboard and Frontend

- New dashboard asset layer integrated with backend rendering
- Real-time update plumbing via WebSocket endpoint
- Modernized CSS/JS component baseline for responsive UI evolution

### Security and Reliability

- Continued emphasis on whitelist-first safe rollout
- Audit-oriented operational pathways in admin surfaces
- Better handling structure around privileged actions

### Project Cleanup and Maintenance

- Removal of generated build/cache/environment artifacts from repository state
- `.gitignore` cleanup and strengthening for Debian/Python workflow artifacts
- Documentation version alignment for the 1.0.0 release line

### Upgrade Notes

1. Back up your current configuration and database before upgrade.
2. Review `config.yaml` for environment-specific whitelist and threshold values.
3. Start in simulation mode after upgrade and validate observed behavior.
4. Re-enable enforcement after confirming policy output and ban quality.

### Known Considerations

- Environment-specific false positives are still possible without correct threshold tuning.
- Some modules introduced in the refactor line may continue to evolve in patch releases.

### Next Direction

- Patch-line stabilization on top of `1.0.x`
- Expanded end-to-end test coverage across CLI/API integration paths
- Continued dashboard UX and operational analytics improvements
