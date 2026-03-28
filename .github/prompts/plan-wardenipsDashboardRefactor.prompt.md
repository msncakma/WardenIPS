# Plan: WardenIPS Dashboard & CLI Professional Refactoring

## TL;DR

Transform WardenIPS from an amateur dashboard implementation into a **production-grade system** with:
1. A **professional CLI tool** (`wardenips-cli`) for full operational control (ban/unban, whitelist management, config hot-reload)
2. **Modular, maintainable dashboard** split from 4800-line monolith into organized service layer + clean routing
3. **Flexible access patterns**: Direct mode (local, fast) + API mode (remote, audited) selectable via `--use-api` flag
4. **Hot-reload capability** for whitelist, firewall rules, and plugin states without service restart
5. **Modern frontend** with improved UX, dark mode, responsive design, WebSockets for real-time updates

---

## Implementation Phases

### Phase 1: Foundation & Infrastructure (Days 1-2)
**Goal**: Create CLI scaffolding and enable hot-reload architecture

#### 1.1 Create CLI Tool Package
- **File**: `wardenips/cli/` (new directory)
  - `__init__.py` — Package initialization
  - `main.py` — Entry point with argparse-based command routing
  - `commands/` (directory)
    - `__init__.py`
    - `ban.py` — Ban/unban IP operations
    - `whitelist.py` — Whitelist CRUD
    - `firewall.py` — Firewall status and reconciliation
    - `config.py` — Config get/patch/reload
    - `plugins.py` — Plugin status and control
    - `database.py` — DB operations and analytics
    - `auth.py` — User/token management (admin only)
  - `client/` (directory) — Shared utilities
    - `__init__.py`
    - `direct.py` — Direct DB/firewall access (requires filesystem + root)
    - `api.py` — HTTP API client using Bearer tokens
    - `exceptions.py` — CLI-specific exceptions

- **File**: `setup.py` — Add CLI entry point
  - New console script: `wardenips-cli = wardenips.cli.main:main`

- **File**: `wardenips/cli/config.json` (template)
  ```json
  {
    "api": {
      "base_url": "http://127.0.0.1:7680",
      "api_key": "",
      "timeout": 10
    },
    "default_mode": "api"  // "api" or "direct"
  }
  ```

#### 1.2 Hot-Reload Infrastructure
- **File**: `wardenips/core/hot_reload.py` (new)
  - `HotReloadManager` class
    - `reload_whitelist()` — Reload whitelist from database without restart
    - `reload_firewall_rules()` — Re-sync active firewall state
    - `reload_plugins_config()` — Update plugin thresholds on-the-fly
    - `reload_notifications()` — Update notification backends
    - Emit events for changes via internal event bus

- **File**: `main.py` (modification)
  - Add async task to listen for hot-reload signals
  - Integrate `HotReloadManager` into `WardenIPS` class
  - Add signal handler for SIGHUP → trigger reload

#### 1.3 Configuration Management Improvements
- **File**: `wardenips/core/config.py` (modification)
  - Add `reload()` method to `ConfigManager` for runtime reload
  - Validate new config before applying (prevent breaking changes)
  - Return diff/validation results

---

### Phase 2: Dashboard Refactoring — Modular Structure (Days 3-5)
**Goal**: Break dashboard.py into logical, testable modules

#### 2.1 Routing Layer (aiohttp blueprints)
Create separate route handlers in `wardenips/api/routes/`:

- `__init__.py` — Route registration helper
- `auth.py` (300 lines)
  - `POST /api/login` — Login with TOTP
  - `POST /api/logout` — Session invalidation
  - `POST /api/session-activity` — Keepalive
  - `GET /api/bootstrap-setup` — Setup wizard
  - `POST /api/bootstrap-confirm` — Confirm setup

- `public.py` (200 lines)
  - `GET /api/health` — Health check
  - `GET /api/stats` — DB statistics
  - `GET /api/events` — Recent events (public/authenticated)
  - `GET /api/bans` — Active ban list
  - `GET /api/firewall` — Firewall status
  - `GET /api/top-attackers` — Top source IPs
  - `GET /api/events-timeline`, `/asn-stats`, `/threat-distribution`, `/plugin-stats`

- `whitelist.py` (150 lines)
  - `GET /api/admin/whitelist` — List whitelist
  - `POST /api/admin/whitelist/add` — Add IP/range
  - `DELETE /api/admin/whitelist/{id}` — Remove
  - `PATCH /api/admin/whitelist/{id}` — Update metadata

- `banning.py` (200 lines)
  - `POST /api/admin/ban-ip` — Manual ban
  - `DELETE /api/admin/ban/{id}` — Unban
  - `POST /api/admin/bulk-ban` — Batch ban
  - `POST /api/admin/firewall/reconcile` — Sync with live state

- `admin.py` (250 lines)
  - `GET/POST /api/admin/users` — User management
  - `GET/POST /api/admin/invites` — Invite system
  - `PATCH /api/admin/roles/{user_id}` — Assign roles
  - `GET /api/admin/audit-log` — Audit log query

- `admin_config.py` (200 lines)
  - `GET /api/admin/config` — Get full config
  - `PATCH /api/admin/config` — Save config changes
  - `POST /api/admin/config/reload` — **(NEW)** Hot-reload config
  - `POST /api/admin/config/validate` — Validate before apply

- `admin_operational.py` (150 lines) **(NEW)**
  - `GET /api/admin/plugins` — Plugin list and status
  - `POST /api/admin/plugins/reload` — Reload plugin configs
  - `GET /api/admin/database/stats` — Extended DB stats
  - `POST /api/admin/database/optimize` — Vacuum/analyze
  - `POST /api/admin/firewall/sync` — Sync with kernel state

- `minecraft.py` (400 lines)
  - All Minecraft-specific endpoints
  - Player tracking, bursts, duplicate emails
  - WebSocket for real-time events

- `pages.py` (300 lines)
  - `GET /` — Homepage router
  - `GET /login` — Login page
  - `GET /dashboard` — Public dashboard HTML
  - `GET /admin` — Admin dashboard HTML
  - `GET /admin/minecraft` — Minecraft intelligence panel
  - `GET /setup` — Setup wizard HTML
  - `GET /static/` — Asset serving

#### 2.2 Service Layer (Business Logic)
Create in `wardenips/api/services/`:

- `__init__.py`
- `auth_service.py` (250 lines)
  - TOTP generation/verification
  - Password hashing validation
  - Session management
  - Bootstrap token handling
  - Rate limiting logic

- `ban_service.py` (200 lines)
  - `ban_ip()` — Apply ban with validation
  - `unban_ip()` — Remove ban from firewall + DB
  - `bulk_ban()` — Batch operations
  - `get_ban_history()` — Query logic
  - Firewall integration with error recovery

- `whitelist_service.py` (150 lines)
  - `add_whitelist_ip()` — Validate and add
  - `remove_whitelist_ip()` — Remove with cascade checks
  - `check_whitelisted()` — Query service
  - ASN/country whitelisting logic

- `config_service.py` (180 lines)
  - `get_config()` — Safe read with secrets masking
  - `patch_config()` — Apply changes with validation
  - `reload_config()` — Trigger hot-reload via HotReloadManager
  - `validate_config_schema()` — JSON schema validation

- `audit_service.py` (100 lines)
  - `log_action()` — Record admin actions
  - `get_audit_log()` — Query with filters
  - User actor attribution

- `plugin_service.py` (150 lines)
  - `get_plugin_status()` — Health checks
  - `reload_plugin()` — Trigger hot-reload
  - `list_plugins()` — Enabled/disabled plugins

- `firewall_service.py` (150 lines)
  - `get_firewall_status()` — Live ipset/iptables state
  - `reconcile_firewall()` — Detect + fix desynchronization
  - `apply_firewall_rule()` — Low-level integration

- `permission_service.py` (100 lines)
  - `check_permission()` — RBAC checks
  - `get_user_permissions()` — Permission enumeration
  - `assign_role()` — Role management

#### 2.3 Models & Schemas
Create `wardenips/api/schemas.py`:
- Pydantic models for all API request/response types
- Input validation and serialization
- Swagger/OpenAPI-compatible definition

---

### Phase 3: Dashboard Class Refactoring (Days 5-6)
**Goal**: Slim down `DashboardAPI` to thin controller layer

#### 3.1 Refactor DashboardAPI Class
- **File**: `wardenips/api/dashboard.py` (rewrite from ~4800 to ~600 lines)
  - Constructor: Inject dependencies (db, firewall, config, services)
  - Remove all business logic → delegate to services
  - Remove HTML rendering → use `pages.render()` helper
  - `async def setup_routes()` — Register all route blueprints
  - Add middleware for:
    - Authentication enforcement
    - RBAC permission checking
    - Audit logging
    - Error handling (JSON error responses)
    - GZIP compression
    - Rate limiting (configurable per endpoint)
  - Remove duplicate code (240+ lines of utility methods)

#### 3.2 Extract HTML Templates
- **Directory**: `wardenips/api/templates/` (new)
  - `base.html` — Common layout
  - `login.html` — Login form
  - `setup.html` — Setup wizard
  - `dashboard.html` — Public read-only dashboard
  - `admin.html` — Admin console
  - `minecraft.html` — Minecraft analytics

- **File**: `wardenips/api/templates/renderer.py` (new)
  - Jinja2 template engine integration
  - Safe template rendering with context validation
  - Static asset URL generation

#### 3.3 Frontend JavaScript/CSS Organization
- **Directory**: `wardenips/api/static/` (create structure)
  - `css/`
    - `base.css` — Common styles
    - `dashboard.css` — Dashboard-specific
    - `admin.css` — Admin panel
    - `minecraft.css` — Minecraft console
    - `dark-mode.css` — Dark theme (NEW)
  - `js/`
    - `api-client.js` — Centralized API calls with error handling
    - `dashboard.js` — Dashboard logic
    - `admin.js` — Admin panel
    - `minecraft.js` — Minecraft console
    - `auth.js` — Session/TOTP handling
    - `utils.js` — Shared utilities (formatting, validation)
  - `lib/` — External libraries (if any)

---

### Phase 4: New Operational Endpoints (Days 6-7)
**Goal**: Enable professional runtime control

#### 4.1 Configuration Management API (wardenips/api/routes/admin_config.py)
- `POST /api/admin/config/reload` — Trigger hot-reload
  - Body: `{ "components": ["whitelist", "firewall", "plugins"] } // optional, all if omitted`
  - Returns: `{ "status": "reloading", "components": [...], "timestamp": "ISO8601" }`

#### 4.2 Operational API (wardenips/api/routes/admin_operational.py)
- `GET /api/admin/plugins` — Map enabled plugins + status
  - Returns: `[{ "name": "ssh", "enabled": true, "log_path": "...", "events_processed": 1234 }, ...]`

- `POST /api/admin/plugins/{name}/reload` — Reload single plugin config
  - Returns: `{ "status": "ok", "plugin": "ssh", "new_config": {...} }`

- `GET /api/admin/firewall/status` — Live firewall state
  - Returns: `{ "ipset_active": 450, "iptables_rules": 12, "simulation_mode": false }`

- `POST /api/admin/firewall/sync` — Reconcile with kernel
  - Returns: `{ "added": 5, "removed": 2, "errors": [], "sync_time_ms": 234 }`

- `GET /api/admin/database/stats` — Extended stats
  - Returns: `{ "total_events": 50000, "table_sizes_mb": {...}, "last_cleanup": "ISO8601" }`

- `POST /api/admin/database/optimize` — VACUUM + ANALYZE
  - Returns: `{ "status": "completed", "time_ms": 5000, "size_before_mb": 450, "size_after_mb": 420 }`

---

### Phase 5: CLI Implementation (Days 7-8)
**Goal**: Full operational CLI tool with dual access modes

#### 5.1 CLI Command Structure
**File**: `wardenips/cli/main.py`

```bash
# General usage:
wardenips-cli [global-options] <command> [command-options]

# Global options:
  --config PATH           # config.yaml path (default: args/env)
  --use-api               # Use API mode instead of direct DB (default: auto-detect)
  --api-url URL           # Override dashboard API URL
  --api-key TOKEN         # Bearer token
  --output {text|json|csv}# Output format (default: text)
  -v, --verbose           # Verbose logging

# Commands:
Commands:
  auth                    # User/token management
  ban                     # Ban operations
  whitelist               # Whitelist management
  firewall                # Firewall control
  config                  # Configuration management
  plugins                 # Plugin management
  database                # Database operations
  status                  # System status report
```

#### 5.2 Ban Commands
```bash
# Ban an IP (permanent)
wardenips-cli ban add 203.0.113.50 --reason "SSH brute-force" --duration 0

# Ban with temporary duration (seconds)
wardenips-cli ban add 203.0.113.50 --duration 3600 --reason "High risk"

# Unban
wardenips-cli ban remove 203.0.113.50

# List active bans
wardenips-cli ban list [--limit 100] [--output json]

# Bulk ban from file
wardenips-cli ban bulk-add /path/to/ips.txt --reason "Blocklist" --duration 7200

# Ban by ASN
wardenips-cli ban add-asn 16509 --reason "Known botnet ASN"
```

#### 5.3 Whitelist Commands
```bash
# Add whitelist entry
wardenips-cli whitelist add 192.168.0.0/16 --reason "Internal network" --tag "office"

# Remove
wardenips-cli whitelist remove 192.168.0.0/16

# List
wardenips-cli whitelist list [--output json]

# By ASN
wardenips-cli whitelist add-asn 8452 --reason "CDN provider"

# Bulk import
wardenips-cli whitelist import /path/to/whitelist.csv
```

#### 5.4 Firewall Commands
```bash
# Status
wardenips-cli firewall status

# Reconcile (sync live state)
wardenips-cli firewall sync [--dry-run]

# Clear all bans (DANGEROUS)
wardenips-cli firewall clear-all --confirm

# Export rules
wardenips-cli firewall export --format ipset > backup.ipset
```

#### 5.5 Config Commands
```bash
# Get config value
wardenips-cli config get dashboard.port
wardenips-cli config get plugins.ssh [--output json]

# Set value
wardenips-cli config set dashboard.port 8080
wardenips-cli config set plugins.ssh.enabled false

# List all (masked)
wardenips-cli config list

# Reload config (hot-reload)
wardenips-cli config reload [--components whitelist,firewall,plugins]

# Validate
wardenips-cli config validate /path/to/config.yaml

# Backup
wardenips-cli config backup --output backup_$(date +%Y%m%d).yaml
```

#### 5.6 Plugin Commands
```bash
# List plugins
wardenips-cli plugins list

# Get plugin status
wardenips-cli plugins status ssh

# Reload plugin config
wardenips-cli plugins reload ssh

# Set plugin option
wardenips-cli plugins set ssh failed_auth_limit 5
wardenips-cli plugins set minecraft observe_only true
```

#### 5.7 Database Commands
```bash
# Stats
wardenips-cli database stats

# Optimize
wardenips-cli database optimize

# Export events
wardenips-cli database export --since 7d --format csv > events.csv

# Query
wardenips-cli database query "SELECT COUNT(*) FROM ban_history"

# Cleanup
wardenips-cli database cleanup --older-than 90d --dry-run
```

#### 5.8 Auth Commands
```bash
# Create admin user
wardenips-cli auth create-user --username admin --password (stdin) [--role admin]

# List users
wardenips-cli auth list-users

# Assign role
wardenips-cli auth assign-role admin admin-role

# Generate API key
wardenips-cli auth generate-key --user admin --expires 30d

# Revoke token
wardenips-cli auth revoke-token <token-id>
```

#### 5.9 Status Command
```bash
# Full system report
wardenips-cli status

# Output:
  System Status Report
  ====================
  Build: WardenIPS v2.0.0 (build 1234, 2026-03-27)
  Uptime: 25d 3h 42m
  
  Components:
    Database: OK (SQLite, 450 MB)
    Firewall: OK (Active: 450 IPs)
    Dashboard: OK (http://127.0.0.1:7680, 3 users)
    Plugins: OK (6 enabled, 1 disabled)
  
  Recent Activity:
    Bans (24h): 127
    Events (24h): 3450
    Whitelist changes: 5
    Config changes: 2
  
  System:
    Memory: 120 MB / 1024 MB
    DB cleanup: 2026-03-20
```

#### 5.10 Implementation Details
- **File**: `wardenips/cli/commands/ban.py` (example structure)
  ```python
  import argparse
  from wardenips.cli.client import get_client  # Returns Direct or API client
  
  def register_commands(subparsers):
      ban_parser = subparsers.add_parser('ban', help='Ban operations')
      ban_subparsers = ban_parser.add_subparsers(dest='action', required=True)
      
      add_parser = ban_subparsers.add_parser('add')
      add_parser.add_argument('ip')
      add_parser.add_argument('--duration', type=int, default=0)
      add_parser.add_argument('--reason')
      add_parser.set_defaults(func=do_ban_add)
  
  async def do_ban_add(args):
      client = get_client(args)
      result = await client.ban_ip(args.ip, args.duration, args.reason)
      print_result(result, args.output)
  ```

#### 5.11 Access Mode Determination (`wardenips/cli/client/__init__.py`)
```python
def get_client(args):
    """Return Direct or API client based on config/args"""
    if args.use_api or 'api' in get_config()['default_mode']:
        # API mode: requires dashboard running + valid token
        return APIClient(
            base_url=args.api_url or config['api']['base_url'],
            api_key=args.api_key or config['api']['api_key'],
            timeout=config['api']['timeout']
        )
    else:
        # Direct mode: requires root + filesystem access
        return DirectClient(
            config_path=args.config,
            db_path=config['database']['path']
        )
```

---

### Phase 6: Frontend Modernization (Days 9-10)
**Goal**: Professional, responsive, modern UX

#### 6.1 Frontend Architecture
- **Framework**: Keep vanilla JS (no heavy deps) but improve structure
- **Styling**: CSS Grid + Flexbox, custom properties for theming
- **Responsiveness**: Mobile-first design, tested on mobile/tablet/desktop
- **Dark Mode**: System preference detection + manual toggle
- **Real-time**: WebSocket-based updates for events, active bans

#### 6.2 Dashboard Pages (Redesign)
- `admin.html` — Refactor to modern UI
  - Sidebar navigation for sections (Stats, Bans, Whitelist, Config, Users, Audit)
  - Cards for stats with trend sparklines
  - Data tables with sorting/filtering/pagination
  - Action buttons (inline + batch)
  - Toast notifications for feedback
  - Modal dialogs for confirmations

- `minecraft.html` — Enhanced Minecraft analytics
  - Real-time player tracking
  - Burst patterns visualization
  - Email duplication warnings
  - Server health metrics

- `dashboard.html` — Public read-only dashboard
  - Heatmap of attacks (canvas + leaflet.js)
  - Top attackers leaderboard
  - Event timeline (zoomable)
  - Threat distribution pie chart
  - Auto-refresh (configurable interval)

- `login.html` — Modern login form
  - TOTP input on same form or separate step
  - Bootstrap token option (initial setup)
  - Form validation feedback
  - Remember device option (optional)

#### 6.3 CSS Improvements
- Reset/normalize to consistent baseline
- CSS custom properties for colors, spacing, fonts (easy theming)
- Semantic HTML5 (form, nav, section, article)
- Accessibility improvements (ARIA labels, keyboard navigation)
- Print stylesheet for reports

#### 6.4 JavaScript Improvements
- Modular ES6 structure (not legacy)
- Fetch API with proper error handling
- Form state management
- Local storage for UI preferences
- WebSocket reconnection logic

---

### Phase 7: Testing & Documentation (Days 11-12)
**Goal**: Ensure quality and maintainability

#### 7.1 Unit Tests
- `tests/api/routes/test_admin_config.py` — Config endpoints
- `tests/api/services/test_ban_service.py` — Ban logic
- `tests/cli/commands/test_ban_commands.py` — CLI ban commands
- `tests/core/test_hot_reload.py` — Hot-reload logic

#### 7.2 Integration Tests
- Full CLI workflows (ban → firewall → database)
- API client vs Direct client parity
- Hot-reload verification
- Config persistence across restarts

#### 7.3 Documentation
- **File**: `CLI_GUIDE.md` (comprehensive CLI reference)
  - Command reference with examples
  - Access mode selection guide
  - Common workflows
  - Troubleshooting

- **File**: `DASHBOARD_ARM.md` (API reference)
  - All endpoints documented
  - Request/response examples
  - Auth methods
  - Error codes

- **File**: `INSTALLATION.md` (update)
  - Installation of CLI tool
  - Configuration setup

---

## Relevant Files to Modify/Create

### Core Files
| File | Action | Lines Est. |
|------|--------|-----------|
| `wardenips/cli/` | **CREATE** new directory | — |
| `wardenips/cli/main.py` | Create | 200 |
| `wardenips/cli/commands/*.py` | Create (8 files) | 1200 |
| `wardenips/cli/client/direct.py` | Create | 400 |
| `wardenips/cli/client/api.py` | Create | 300 |
| `wardenips/api/routes/` | **CREATE** new directory | — |
| `wardenips/api/routes/*.py` | Create (8 files) | 2500 |
| `wardenips/api/services/` | **CREATE** new directory | — |
| `wardenips/api/services/*.py` | Create (8 files) | 2000 |
| `wardenips/api/dashboard.py` | **REFACTOR** | 4800 → 600 |
| `wardenips/api/schemas.py` | Create | 300 |
| `wardenips/core/hot_reload.py` | Create | 250 |
| `wardenips/core/config.py` | Modify | +reload() |
| `wardenips/api/templates/` | **CREATE** new directory | — |
| `wardenips/api/templates/*.html` | Create (6 files) | 1500 |
| `wardenips/api/static/` | **REORGANIZE** | — |
| `setup.py` | Modify | +CLI entry point |
| `main.py` | Modify | +HotReloadManager integration |

### Tests
| File | Lines |
|------|-------|
| `tests/api/routes/` | 1200 |
| `tests/api/services/` | 1000 |
| `tests/cli/` | 1000 |
| `tests/core/test_hot_reload.py` | 400 |

### Documentation
| File | Lines |
|------|-------|
| `CLI_GUIDE.md` | 1000+ |
| `DASHBOARD_API.md` | 800+ |
| `ARCHITECTURE_UPDATED.md` | 500+ |

---

## Verification Steps

### Phase 1 Verification
1. ✅ CLI package imports without errors
2. ✅ Help output: `wardenips-cli --help`
3. ✅ SIGHUP signal triggers hot-reload
4. ✅ Config reload validates before applying

### Phase 2 Verification
1. ✅ Each route module registers successfully
2. ✅ All old dashboard.py endpoints still work
3. ✅ Services can be instantiated independently
4. ✅ No more duplicate utility functions

### Phase 3 Verification
1. ✅ DashboardAPI class reduced to <700 lines
2. ✅ HTML templates render correctly (Jinja2)
3. ✅ Static assets served with correct paths

### Phase 4 Verification
1. ✅ Curl requests to new endpoints succeed
2. ✅ Hot-reload endpoints return correct status
3. ✅ Firewall sync reconciles db ↔ kernel state

### Phase 5 Verification
1. ✅ `wardenips-cli ban add 203.0.113.50` → IP banned
2. ✅ `wardenips-cli --use-api ban list` → Lists via API
3. ✅ `wardenips-cli config reload` → Config hot-reloaded
4. ✅ `wardenips-cli status` → System report printed

### Phase 6 Verification
1. ✅ Dashboard renders on mobile (375px width)
2. ✅ Dark mode toggle works
3. ✅ Forms submit successfully
4. ✅ WebSocket updates real-time

### Phase 7 Verification
1. ✅ All unit tests pass (`pytest tests/`)
2. ✅ Coverage >80%
3. ✅ CLI workflows documented with examples
4. ✅ API schema can be imported by OpenAPI tools

---

## Architecture Decisions

### Decision 1: CLI Access Modes
- **Direct** (local, fast): No HTTP overhead, requires root + filesystem
- **API** (remote, audited): Uses dashboard API, requires network + auth
- **Auto-detect**: CLI tries direct first, falls back to API if unavailable
- **Rationale**: Flexibility for both local automation and remote management

### Decision 2: Modular Routes + Service Layer
- **Why split**: Separation of concerns, easier testing, reusability
- **Routes** = HTTP request/response handling
- **Services** = Business logic (can be called from routes, CLI, or other systems)
- **Rationale**: Professional architecture, testable independently

### Decision 3: Hot-Reload Architecture
- Use signal-based triggers (SIGHUP) or API endpoint
- Re-load config, re-construct affected components
- Support partial reload (whitelist, firewall, etc.) not full restart
- **Rationale**: Zero-downtime updates, enterprise requirement

### Decision 4: Template Organization
- HTML templates in separate files (not embedded strings)
- Jinja2 rendering engine (familiar to web devs)
- **Rationale**: Maintainability, easier styling iteration, separation of concerns

### Decision 5: Frontend Framework
- Keep vanilla JavaScript (no React/Vue)
- Improve code organization and modularity
- **Rationale**: Reduces dependencies, faster load times, simpler deployment

---

## Scope & Exclusions

### IN SCOPE
- ✅ Dashboard refactoring (modular, clean)
- ✅ Full-featured CLI tool
- ✅ Config hot-reload capability
- ✅ New operational API endpoints
- ✅ Frontend modernization
- ✅ Comprehensive testing
- ✅ Full documentation

### OUT OF SCOPE (explicitly excluded)
- ❌ Database schema changes (existing schema is fine)
- ❌ Plugin API changes (plugin interface remains stable)
- ❌ Authentication redesign beyond current TOTP/sessions
- ❌ Frontend framework migration (staying vanilla JS)
- ❌ Kubernetes/Helm chart packaging
- ❌ Third-party integrations (e.g., Prometheus metrics, ELK stack)

---

## Timeline Summary
- **Phase 1 (Foundation)**: 2 days
- **Phase 2 (Dashboard Routes)**: 3 days
- **Phase 3 (Dashboard Refactor)**: 2 days
- **Phase 4 (New Endpoints)**: 1-2 days
- **Phase 5 (CLI Tool)**: 2 days
- **Phase 6 (Frontend)**: 2 days
- **Phase 7 (Testing & Docs)**: 2 days
- **Total**: ~12-14 days (concurrent phases possible)

---

## Further Considerations

### Q1: Should CLI be in same Python package or separate tool?
**Recommendation**: Same package (`wardenips.cli`), installable via `setup.py` console_scripts entry point.
- **Pros**: Single install, version-locked, easier distribution
- **Cons**: Slightly larger package size
- **Alternative**: Separate `wardenips-cli` package (more complex packaging)

### Q2: How to handle CLI config file vs. Dashboard API key persistence?
**Recommendation**: Single config source `~/.wardenips/config.json` (user home dir)
- Stores API URL, API key, default access mode
- CLI tools use this to auto-populate `--api-key`, `--api-url`
- Dashboard stores session in memory (transient)

### Q3: Should hot-reload support plugins dynamically?
**Recommendation**: Yes, but with validation
- Reload plugin config (thresholds, log paths)
- Don't allow hot-addition of new plugins (requires full restart)
- Validate new config before applying to avoid crashes

---

## Success Criteria

A successful implementation will have:
1. ✅ Professional CLI tool replacing manual database queries
2. ✅ Dashboard modularized (all routes in `api/routes/`, logic in `services/`)
3. ✅ Config hot-reload working without service restart
4. ✅ 100% parity between CLI (--use-api) and Dashboard endpoints
5. ✅ Modern, responsive frontend with dark mode
6. ✅ Comprehensive test coverage (>80%)
7. ✅ Full documentation (CLI guide, API reference, architecture update)
8. ✅ Zero breaking changes to plugin interface or database schema
