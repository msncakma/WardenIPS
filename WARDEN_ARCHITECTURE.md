# WardenIPS - System Architecture (v1.0.0+)

## Executive Summary

WardenIPS is a **professional Linux-native intrusion prevention system** with:
- **Dual-mode operational interface**: CLI (direct + API) and REST API
- **Service-oriented architecture**: Modular business logic layer
- **Zero-downtime hot-reload**: Config updates without service restart
- **Role-based access control**: Admin, Operator, Viewer, Analyst roles
- **Comprehensive audit logging**: Track all sensitive operations
- **Production-grade CLI tool**: `wardenips-cli` for operational control

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      WardenIPS Ecosystem                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐           ┌──────────────────┐           │
│  │  wardenips-cli   │           │   REST API       │           │
│  │  (Direct/API     │           │  aiohttp on      │           │
│  │   mode)          │           │  port 8080       │           │
│  └────────┬─────────┘           └────────┬─────────┘           │
│           │                              │                     │
│           └──────────────┬───────────────┘                     │
│                          │                                     │
│                   ┌──────▼──────┐                             │
│                   │  Client     │                             │
│                   │  Factory    │                             │
│                   │ (get_client)│                             │
│                   └──────┬──────┘                             │
│                          │                                     │
│          ┌───────────────┼───────────────┐                    │
│          │               │               │                    │
│    ┌─────▼─────┐   ┌────▼────┐   ┌─────▼─────┐               │
│    │ DirectMode│   │APIClient│   │ConfigMode │               │
│    │(root req) │   │(auth req)   │(internal) │               │
│    └─────┬─────┘   └────┬────┘   └─────┬─────┘               │
│          │               │               │                    │
│    ┌─────▼─────────────────────┬────────────┬─────┐           │
│    │                           │            │     │           │
│    ▼                           ▼            ▼     ▼           │
│ ┌─────────────┐   ┌──────────────────┐   ┌────────────────┐  │
│ │   Core      │   │   Services       │   │   Managers     │  │
│ ├─────────────┤   ├──────────────────┤   ├────────────────┤  │
│ │             │   │                  │   │                │  │
│ │ - main.py   │   │ - BanService     │   │ - DatabaseMgr  │  │
│ │ - config.py │   │ - AuthService    │   │ - FirewallMgr  │  │
│ │ - auth.py   │   │ - WhitelistSvc   │   │ - ConfigMgr    │  │
│ │ - logger.py │   │ - ConfigService  │   │ - LogTailer    │  │
│ │ - scoring.py│   │ - FirewallSvc    │   │ - PluginMgr    │  │
│ │ - models.py │   │ - PermissionSvc  │   │ - HotReloadMgr │  │
│ │ - etc.      │   │ - AuditService   │   │ - ASNLookup    │  │
│ │             │   │                  │   │ - Whitelist    │  │
│ └─────────────┘   └──────────────────┘   └────────────────┘  │
│         │                    │                     │          │
│         └────────────────────┼─────────────────────┘          │
│                              ▼                                │
│                    ┌──────────────────┐                      │
│                    │   Persistence    │                      │
│                    ├──────────────────┤                      │
│                    │ SQLite Database  │                      │
│                    │ YAML Config      │                      │
│                    │ Log Files        │                      │
│                    └──────────────────┘                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```