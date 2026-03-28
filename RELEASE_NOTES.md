# WardenIPS Release Notes

## v1.0.1-beta-7 - CLI Circular Import and Command Parser Fix

Release date: 2026-03-28

### Fixed

- Removed invalid eager imports from `wardenips.cli.commands` package initializer that referenced non-existent modules (`auth`, `plugins`, `status`).
- Resolved startup crash: `ImportError: cannot import name 'auth' from partially initialized module wardenips.cli.commands`.
- Added parser registrations for `plugins`, `auth`, and `status` command groups so wrapper-forwarded commands are recognized consistently.

### Impact

- `wardenips cli` and `wardenips auth` no longer fail during module import.
- Placeholder command groups return controlled not-implemented messages instead of import-time crashes.

## v1.0.1-beta-6 - Missing CLI Dependency Fix

Release date: 2026-03-28

### Fixed

- Added missing `tabulate` dependency to `requirements.txt`.
- Fixes runtime crash for CLI commands that render table output (`ban`, `whitelist`, `config`, `database`, `firewall`).

### Impact

- `wardenips` CLI subcommands no longer fail with `ModuleNotFoundError: No module named 'tabulate'` after install/update.

## v1.0.1-beta-5 - Installer Update Source Fix

Release date: 2026-03-28

### Fixed

- Resolved update flow where running `install.sh` from `/opt/wardenips` could skip file deployment entirely.
- Installer now detects non-git `/opt/wardenips` installs and automatically fetches the latest repository snapshot before deploying files.
- This ensures wrapper and CLI updates are actually applied on hosts installed from packaged snapshots.

### Impact

- Fixes cases where users kept seeing old wrapper behavior (`ModuleNotFoundError` / missing new commands) even after rerunning installer.

## v1.0.1-beta-4 - CLI Module Import Path Fix

Release date: 2026-03-28

### Fixed

- Resolved `ModuleNotFoundError: No module named 'wardenips'` for wrapper CLI commands such as `wardenips cli`, `wardenips whitelist`, and `wardenips status-cli`.
- Wrapper now sets `PYTHONPATH=/opt/wardenips` when invoking `-m wardenips.cli.main`, ensuring module discovery even when the package is not installed into site-packages.
- Applied the same fix to the installer-generated wrapper template for consistency on fresh installs and updates.

## v1.0.1-beta-3 - CLI Permission Fallback and Alias Fix

Release date: 2026-03-28

### Fixed

- Resolved `Permission denied` errors when running wrapper CLI commands (`ban`, `whitelist`, `database`, `auth`, etc.) as non-root users.
- Wrapper now auto-falls back to `sudo -u wardenips` for CLI/main operations when direct runtime access is blocked by filesystem permissions.
- Added `plugin` alias support so `wardenips plugin ...` now maps to `wardenips plugins ...`.

### Notes

- Security model remains intact: installation directory can stay locked down while wrapper keeps commands usable.
- Installer template was updated, so fresh installs/updates generate the corrected wrapper behavior.

## v1.0.1-beta-2 - CLI Wrapper Exposure Fix

Release date: 2026-03-28

### Fixed

- `wardenips` wrapper now exposes new operational CLI command groups directly in help output.
- You can now run these from the wrapper directly: `ban`, `whitelist`, `firewall`, `database`, `plugins`, `auth`.
- Added pass-through modes:
	- `wardenips cli ...`
	- `wardenips config-cli ...`
	- `wardenips status-cli ...`

### Notes

- Existing service commands (`start`, `stop`, `restart`, `status`, `logs`) remain unchanged.
- `config` remains reserved for printing config path in wrapper; use `config-cli` for CLI config subcommands.

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
