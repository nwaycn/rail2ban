# rail2ban

A Rust reimplementation of [fail2ban](https://github.com/fail2ban/fail2ban), aiming for behavioral
parity with fail2ban 1.1.x while delivering a single, fast, memory-safe binary with a built-in
web management interface.

> **Why rail2ban?** Python-based fail2ban can peg dozens of CPU cores under log storms — the
> interpreter overhead of per-line regex matching is amplified exactly when you are under attack.
> rail2ban was written from scratch in Rust (with AI assistance, modeled on fail2ban's behavior)
> to provide a drop-in, configuration-compatible runtime that is both **fast** and **stable**
> under extreme load.

---

## Table of Contents

- [Why Another Wheel?](#why-another-wheel)
- [The Four Binaries](#the-four-binaries)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Compatibility](#configuration-compatibility)
- [Security Design](#security-design)
- [Performance](#performance)
- [Deployment](#deployment)
- [Tech Stack](#tech-stack)
- [Documentation](#documentation)
- [License](#license)

---

## Why Another Wheel?

fail2ban has guarded servers since 2004 — its filter and action ecosystem is an invaluable
asset. But its Python implementation has unavoidable pain points under high load:

| Dimension | fail2ban | rail2ban |
|---|---|---|
| Language | Python | Rust (zero-cost abstractions, no GC) |
| Async model | multi-threaded poll | tokio async |
| Database | SQLite (single history table) | SQLite (`bans` history + `bips` current state) |
| Config compat | native | reads `/etc/fail2ban` directly |
| Web management | none | built-in authenticated Dashboard |
| Deployment | requires Python runtime | single binary, `scp` and run |

rail2ban is **not** a replacement for fail2ban's ecosystem — it is a faster, safer runtime for
that same ecosystem.

---

## The Four Binaries

All four binaries share the same `rail2ban` library crate.

```
rail2ban-server    ← the daemon (the brain)
rail2ban-client    ← CLI client (the mouth)
rail2ban-regex     ← offline regex tester (the microscope)
rail2ban-web       ← web management UI (the face)
```

### 1. `rail2ban-server` — The Daemon

Long-running background process doing the heavy lifting:

- Loads jail configs from `/etc/rail2ban`
- Watches log files via `inotify` (event-driven, not sleep-polling)
- Runs regex matching per line, hands hits to `FailManager` for counting
- When `maxretry` is reached, `BanManager` runs `actionban` (iptables/firewalld)
- Listens on a Unix socket for client queries and control commands

Unix socket (not TCP) for **security**: file mode `0600`, root-only, no network port exposed.

### 2. `rail2ban-client` — The CLI Client

Stateless CLI that sends requests to the server over the Unix socket:

```bash
rail2ban-client status                 # overall status
rail2ban-client status sshd            # per-jail ban list
rail2ban-client ban-ip sshd 1.2.3.4    # manual ban
rail2ban-client unban-ip 1.2.3.4       # unban one
rail2ban-client unban --all            # unban all
rail2ban-client reload                 # reload config
```

Output is structured JSON, composable with monitoring systems and Ansible playbooks.

### 3. `rail2ban-regex` — Offline Regex Tester

Standalone debugging tool — no server connection, no iptables changes:

```bash
rail2ban-regex /var/log/secure 'Failed password for .* from <HOST>'   # inline regex
rail2ban-regex --filter sshd /var/log/secure                          # named filter
rail2ban-regex -v /var/log/secure sshd                                # verbose
```

Reports total lines, matched lines, and unique hosts. Use it to validate a new jail before
going live — catches both missed attackers and false-positive bans.

### 4. `rail2ban-web` — Web Management UI

The headline addition over fail2ban: an authenticated web dashboard. It embeds a full
rail2ban server, so **one process** runs both the daemon and the HTTP API:

```bash
rail2ban-web \
  --conf /etc/rail2ban \
  --listen 0.0.0.0:8080 \
  --authdb /var/lib/rail2ban/rail2ban-auth.db
```

Open `http://your-server:8080/emc/` (path is `/emc/`, not `/admin/` — a small
**security-through-obscurity** touch that filters low-effort scanners).

**First run:** the dashboard shows a "create admin" screen; set username + password
(strength enforced) and it is written to the auth DB. That screen never appears again.

**Dashboard features:**

| Block | Function |
|---|---|
| Stat cards | total jails, active jails, currently banned IPs, bans today |
| Chart.js | ban-trend line chart, per-jail distribution pie |
| Jail console | per-jail row: status light, start/stop/restart, ban count, params |
| Ban list | searchable, manual unban, bulk `unban all` |

**Convenience details:**

- 5s auto-refresh (toggleable), pauses while a modal is open
- Keyboard shortcuts: `Ctrl+B` jump to bans, `Ctrl+U` unban all, `Enter` confirm, `Esc` close
- Parallel API calls (`Promise.all`) cut first paint from ~800ms to ~200ms
- Toast notifications for every action
- Built-in log viewer with level selector (CRITICAL → DEBUG)

**REST API** (all under `/emc/api/`, session-cookie protected except auth endpoints):

```
POST   /login            POST   /logout           GET    /session
POST   /setup            POST   /change-password  GET    /admin/info
GET    /status           GET    /stats            GET    /version
GET    /jails            GET    /jails/:name
POST   /jails/:name/start  POST /jails/:name/stop  POST /jails/:name/restart
GET    /bans             POST   /bans             DELETE /bans/:ip  DELETE /bans
GET    /config           POST   /config/reload    GET    /log
```

**Deployment modes:**

- **Bare:** `rail2ban-web --listen 0.0.0.0:8080` — intranet/test
- **Reverse proxy:** Nginx in front + `rail2ban-web --listen 127.0.0.1:8080 --trust-proxy` —
  Nginx handles TLS and forwards the real client IP

---

## Installation

### Prerequisites

- Rust 1.75+ (1.92 stable recommended)
- C compiler (GCC or Clang) — for the bundled SQLite library
- Linux: systemd development headers (for the journal backend)

### Build from Source

```bash
git clone https://github.com/rail2ban/rail2ban.git
cd rail2ban
cargo build --release
```

Artifacts land in `target/release/`:

| File | Description |
|---|---|
| `rail2ban-server` | daemon |
| `rail2ban-client` | CLI client |
| `rail2ban-regex` | regex testing tool |
| `rail2ban-web` | web management interface |

### Install to System

```bash
sudo cp target/release/rail2ban-* /usr/local/bin/
sudo mkdir -p /etc/rail2ban /var/run/rail2ban /var/lib/rail2ban
sudo chown root:root /var/run/rail2ban /var/lib/rail2ban
```

No Python, no `pip install`, no virtualenv — just copy the binaries.

---

## Quick Start

### 1. Minimal Config

Create `/etc/rail2ban/jail.conf`:

```ini
[DEFAULT]
bantime  = 10m
findtime = 10m
maxretry = 3
backend  = auto

[sshd]
enabled = true
filter  = sshd
logpath = /var/log/auth.log
action  = iptables-multiport[name=sshd, port=ssh, protocol=tcp]
```

Create `/etc/rail2ban/fail2ban.conf`:

```ini
[Definition]
loglevel  = INFO
logtarget = STDOUT
socket    = /var/run/rail2ban/rail2ban.sock
dbfile    = /var/lib/rail2ban/rail2ban.sqlite3
```

### 2. Validate Config

```bash
rail2ban-server -t
# -> "configuration OK (1 jails)"
```

### 3. Run

```bash
# Foreground (debug)
rail2ban-server -f

# Or run the web UI (embeds the daemon)
rail2ban-web --conf /etc/rail2ban --listen 0.0.0.0:8080

# Check status
rail2ban-client status
```

### 4. Migrate from fail2ban

Existing fail2ban configs work as-is:

```bash
rail2ban-server --conf /etc/fail2ban --test
# -> "configuration OK" means you can switch over
```

Do **not** run fail2ban and rail2ban simultaneously against the same logs.

---

## Configuration Compatibility

rail2ban intentionally mirrors fail2ban's config layout:

- Config dirs default to `/etc/rail2ban`, `/etc/fail2ban` — reads legacy configs directly
- `jail.local`, `filter.d/*.conf`, `action.d/*.conf` formats are identical
- Variable interpolation `<HOST>`, `<ip>`, `failregex`, `ignoreregex` all supported
- `bantime.increment`, `bantime.maxtime`, `findtime`, `maxretry`, `usedns` all supported
- Config load order: `jail.conf` → `jail.d/*.conf` → `jail.local` → `jail.d/*.local`

---

## Security Design

The biggest worry with a web management UI is: **does it become an attack surface itself?**
rail2ban treats this seriously.

### Argon2id + Timing-Attack Mitigation

Password hashing uses **Argon2id** (Password Hashing Competition winner). For non-existent
users, a dummy Argon2 verification still runs so response time matches the real-user path —
defeating username enumeration via timing differences.

### Two-Layer Brute-Force Protection

1. **In-memory sliding window:** 5 failures per IP per 15 min → 15 min lockout. `IndexMap`
   backed, O(1) lookup, background cleanup every 5 min.
2. **DB-persisted attempts:** all login tries are logged to SQLite; `count_recent_failures(ip)`
   survives process restarts.

### Session Management

- 256-bit random token (`OsRng`); cookie is `HttpOnly`, `SameSite=Strict`, `Path=/emc`
- Idle timeout 8h, absolute timeout 24h
- Changing the password immediately invalidates all existing sessions

### Trust-Proxy Mode

`--trust-proxy` is **off by default**. Only when explicitly enabled will rail2ban read
`X-Forwarded-For` / `X-Real-IP`; otherwise the TCP remote address is used. Prevents header
spoofing from bypassing rate limits.

### Security Headers + XSS Prevention

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`X-XSS-Protection: 1; mode=block`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
All dynamic `innerHTML` in the dashboard passes through an `esc()` HTML-escape function.

---

## Performance

### Event-Driven Log Watching

`inotify` replaces fail2ban's `time.sleep(1)` polling — log writes trigger matching in
milliseconds, not seconds.

### The `bips` Table: Zero-Duplicate State Recovery

A key improvement over fail2ban. The DB has two tables:

| Table | Meaning | Operation |
|---|---|---|
| `bans` | historical ban records (append-only) | audit & stats |
| `bips` | **current** ban state (one row per jail+ip) | insert on ban, delete on unban |

On restart, rail2ban only restores from `bips` — expired bans are ignored, no duplicates.

### actioncheck → actionrepair Flow

Before `actionban`, rail2ban runs `actioncheck`; on failure it runs `actionrepair` then
retries. Handles the "someone manually flushed iptables" edge case that simplified rewrites
often skip.

### Multi-Line `LineBuffer`

For `maxlines > 1` filters (Java stacktraces, etc.), `LineBuffer` accumulates lines before
feeding the regex engine — avoids half-stacktrace match failures.

### IgnoreCache

Caches `ignorecommand` results with TTL + LRU eviction, so hot IPs skip the external script
call on every log line.

---

## Deployment

### systemd Unit

Create `/etc/systemd/system/rail2ban.service`:

```ini
[Unit]
Description=rail2ban Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rail2ban-server -f
ExecStop=/usr/local/bin/rail2ban-client stop
PIDFile=/var/run/rail2ban/rail2ban.pid
Restart=on-failure
RuntimeDirectory=rail2ban

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rail2ban
```

For the web UI, swap `ExecStart` to:

```ini
ExecStart=/usr/local/bin/rail2ban-web --conf /etc/rail2ban --listen 0.0.0.0:8080
```

### Logrotate

`/etc/logrotate.d/rail2ban`:

```
/var/log/rail2ban.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        /usr/local/bin/rail2ban-client flushlogs
    endscript
}
```

### Cross-Distro Build Tip

For maximum glibc compatibility (e.g. targeting CentOS 7.9), build on the oldest supported
OS you have. The release profile uses `lto = "thin"` and `strip = "debuginfo"` for a small,
fast binary.

---

## Tech Stack

| Purpose | Dependency |
|---|---|
| Async runtime | tokio (full) |
| Web framework | axum 0.7 |
| Middleware | tower, tower-http |
| Password hashing | argon2 0.5 |
| Regex engine | regex + fancy-regex |
| CLI | clap 4 |
| Database | rusqlite (bundled) |
| Logging | tracing + tracing-subscriber |
| File watching | inotify (Linux) |
| Serialization | serde + serde_json + toml |
| Date/time | chrono |
| IP / CIDR | ipnet |

65 tests pass, zero clippy warnings.

---

## Documentation

- **Full manual (Chinese):** [`docs/MANUAL.md`](docs/MANUAL.md) — 900+ lines covering
  installation, configuration, commands, filter tags, variable interpolation, ban-time
  increment, database schema, deployment, fail2ban differences, and troubleshooting.
- **Technical spec:** [`docs/SPEC.md`](docs/SPEC.md)
- **WeChat article (Chinese):** [`docs/WECHAT_ARTICLE.md`](docs/WECHAT_ARTICLE.md) — the
  design-story version of this README.

---

## License

GPL-2.0-or-later.
