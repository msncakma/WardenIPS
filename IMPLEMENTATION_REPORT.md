# WardenIPS Implementation Report

## Scope of this change set

This delivery turns the dashboard authentication path from a config-secret-only model into a first-boot enrollment and managed admin account flow.

The main objective was to harden the admin surface without breaking existing installs.

Implemented areas:

- First-boot bootstrap enrollment for fresh installs
- Managed admin account storage in SQLite and Redis backends
- Argon2 password hashing
- TOTP-based second factor during setup and login
- Audit logging for high-risk admin actions
- Login and setup UI changes to support staged authentication
- Installer changes that generate and display a bootstrap token
- Documentation updates so operators can actually follow the new flow

## What changed

### 1. First-boot bootstrap setup

Fresh installs now land in a setup-required state.

The installer generates:

- a random bootstrap token
- a stored SHA-256 hash of that token
- a 24-hour expiry timestamp

These values are written into `dashboard.bootstrap` inside `config.yaml`.

While setup is active:

- `/setup` is available
- `/login` redirects to `/setup`
- `/admin` is blocked until setup completes
- root redirects to `/setup`

When setup completes successfully:

- the first admin user is created in the selected backend
- TOTP is enabled for that user
- the bootstrap token state is cleared from config
- an authenticated admin session is issued immediately

### 2. Managed admin users

Admin users are no longer limited to static credentials stored in config.

New backend methods were added so both SQLite and Redis can support:

- checking whether admin users exist
- looking up an admin user by username
- creating the first admin user
- recording successful admin logins
- storing audit log events

For SQLite, two new tables were added:

- `admin_users`
- `audit_log`

For Redis, matching structures were added so the feature works in either backend mode.

### 3. Password hashing and TOTP

Authentication helpers now live in `wardenips/core/auth.py`.

This module provides:

- Argon2 password hashing and verification
- bootstrap token hashing and verification
- TOTP secret generation
- TOTP URI generation for authenticator apps
- QR code generation as inline data URLs
- password policy validation

Dependencies added:

- `argon2-cffi`
- `pyotp`
- `qrcode[pil]`

### 4. Login flow changes

The login flow is now mode-aware.

If managed admin users exist:

1. username and password are verified against the backend
2. if TOTP is enabled, a short-lived pending login token is created
3. the browser submits a TOTP code to finish authentication
4. a session is issued and login metadata is recorded

If managed admin users do not exist yet:

- legacy config-based credentials still work for backward compatibility
- `dashboard.password` remains the preferred fallback
- `dashboard.api_key` remains accepted when no password is configured

This keeps older deployments working while allowing fresh installs to use the stronger path.

### 5. Setup flow changes

The setup page is a two-step enrollment flow.

Step 1:

- operator enters bootstrap token
- operator chooses a non-default admin username
- operator sets a strong password

Step 2:

- server generates a TOTP secret
- server returns a QR code and secret
- operator scans the secret into an authenticator app
- operator proves possession by submitting a current TOTP code

Only after that second step is the admin account persisted.

### 6. Audit logging

An audit trail is now recorded for:

- login failures
- login successes
- TOTP failures
- setup start and completion outcomes
- manual unban actions
- ban deactivation actions
- firewall flushes
- event-history clearing
- ban-history clearing
- test notification dispatches
- full config saves
- config patch updates

Each audit record can include:

- actor username
- action name
- request IP address
- target or affected entity
- structured details payload

### 7. Dashboard UI updates

The admin access UI is no longer a single static login form.

New behavior:

- staged password then TOTP login when required
- first-boot setup page at `/setup`
- clearer operator messaging when setup is still required
- UI hints that distinguish managed auth from legacy fallback auth

### 8. Installer behavior

The installer now differentiates more clearly between fresh install and update paths.

Fresh install behavior:

- generate bootstrap token
- store only its hash in config
- mark setup as required
- blank legacy dashboard username/password defaults
- print setup URL, token, and expiry in the final summary

Update behavior:

- does not force bootstrap setup
- preserves existing operational auth behavior

## File summary

Core files changed in this delivery:

- `install.sh`
- `requirements.txt`
- `config.yaml`
- `config_backup.yaml`
- `README.md`
- `wardenips/core/auth.py`
- `wardenips/core/database.py`
- `wardenips/core/redis_backend.py`
- `wardenips/api/dashboard.py`

## Operational notes

- Fresh installs should be fronted by a TLS reverse proxy before exposing the dashboard externally.
- Existing installs can continue using legacy dashboard credentials until they migrate.
- The bootstrap token is intentionally one-time and time-bounded.
- Admin sessions remain idle-expiring.
- TOTP setup is enforced for the first managed admin account.

## Remaining follow-up work

This is the first major production-hardening wave, not the end state.

Recommended next work:

1. Add admin user management for creating, rotating, disabling, and revoking operators from the UI.
2. Add backup or recovery codes for TOTP loss scenarios.
3. Add reverse-proxy deployment examples with TLS and trusted proxy handling.
4. Expose audit log review in the admin UI.
5. Add signed or mutually authenticated threat-mesh transport before calling that channel production-grade.
6. Expand test coverage around bootstrap setup, login challenges, and backend compatibility.

## Intended outcome

After this change set, WardenIPS is in a materially better position for controlled production deployment because:

- fresh installs no longer depend on a long-lived default-style admin path
- privileged access can use password plus TOTP
- sensitive admin actions leave an audit trail
- existing installs remain compatible instead of being broken by a forced migration
