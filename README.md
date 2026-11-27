# Fail2ban Guard (`io.github.3130585774.fail2ban`)

Real-time intrusion detection and automatic IP banning plugin for **Nginx UI v3**.

Monitor Nginx access logs and admin login failures, automatically block malicious IPs with built-in customizable jails, manage bans & whitelists directly inside Nginx UI's plugin settings drawer, and expose active bans natively to Nginx UI's **Blocklists** system.

## Features

- **6 Built-in Detection Rules (Jails)** — All configurable online with enable toggles, thresholds, time windows, and ban durations:

  | Rule ID | Purpose | Default Policy |
  | --- | --- | --- |
  | `http-404-scan` | Detects rapid 404 scanning across distinct paths (ignores static assets) | `15 / 60s` → `1h` |
  | `http-sensitive-probe` | Blocks probes against `/.env`, `/.git/`, `/wp-login.php`, `/phpmyadmin`, etc. | `3 / 5m` → `24h` |
  | `http-auth-bruteforce` | Blocks repeated `401` / `403` failures on login/auth paths (`/login`, `/auth`, `/api/auth`, etc.; **disabled by default**) | `10 / 3m` → `30m` |
  | `http-bad-bot` | Blocks known vulnerability scanners (`sqlmap`, `nikto`, `zgrab`, `nuclei`, etc.) | `2 / 60s` → `24h` |
  | `nginxui-login-guard` | Protects Nginx UI admin login via `auth.login_failed` events | `5 / 10m` → `1h` |
  | `recidive-escalation` | Escalates repeat offenders over a 7-day rolling window | `1h → 24h → 7d` |

- **Two Native Enforcement Modes**:
  1. **Nginx UI Blocklists (`security.blocklist`)** — Add **Fail2ban Active Bans** directly in **Blocklists** without manual Nginx config edits.
  2. **Real-Time Nginx Snippet (`nginx.snippet`)** — Debounced (3s / 10s max wait) automatic snippet writer with SHA-256 deduplication and auto-sharding under 256 KiB.
- **Anti-Lockout & Whitelist Protection** — Hardcoded protection for `127.0.0.0/8`, `::1`, `0.0.0.0/0`, `::/0` plus custom admin CIDR whitelists (adding a whitelist CIDR automatically unbans matching active IPs).
- **Deep Nginx UI Integration** — Native Plugin Settings Drawer UI (narrow-drawer friendly card layout, Light/Dark theme sync, full `zh_CN` / `en` localization) plus access log **Threat Analysis** view & **Threat Hits (24h)** column.
- **Low Memory & Crash-Safe** — Bounded 64-shard LRU tracker (`GOMEMLIMIT=100MiB`) and SQLite WAL persistence. Never logs raw client IPs, URLs, or User-Agents to stderr or host logs.

## Reverse Proxy / CDN (`real_ip`) Notice

If your Nginx instance sits behind a reverse proxy, load balancer, or CDN (such as Cloudflare, AWS ALB, or frp), **configure Nginx's `ngx_http_realip_module` before enabling Fail2ban Guard**. Otherwise Nginx access logs will record the proxy/CDN IP instead of the real visitor IP, which could cause Fail2ban Guard to ban your own proxy or CDN edge IP.

Example (`http {}` block):

```nginx
# Trust only your reverse proxy / CDN IP ranges
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
# Use CF-Connecting-IP for Cloudflare, or X-Forwarded-For / X-Real-IP for standard proxies
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

You should also add your proxy/management IP ranges to **Admin Whitelist** in the plugin settings.

## Supported platforms

- `linux-amd64` (static binary, `CGO_ENABLED=0`)
- `linux-arm64` (static binary, `CGO_ENABLED=0`)
- `darwin-arm64` (macOS Apple Silicon)

## Quick Start

1. Install and enable **Fail2ban Guard** from the Nginx UI Plugin Marketplace (or upload the `.tar.gz` release package).
2. Open **System → Plugins → Fail2ban Guard → Settings** to:
   - Toggle protection, manually ban/unban IPs, or extend bans
   - Adjust jail thresholds and ban durations
   - Add your admin IP / CIDR to the whitelist
3. Enable enforcement using either method:
   - **Recommended**: Go to **Blocklists** in Nginx UI and add the **Fail2ban Active Bans** source.
   - **Real-Time Snippet**: Add the following directive to your Nginx `http {}` or target `server {}` block:
     ```nginx
     include snippets/plugins/io.github.3130585774.fail2ban/fail2ban-bans.conf;
     ```

## Development & Packaging

### Run Tests

```bash
go vet ./...
go test -v -race ./...
go test -bench=BenchmarkDetector5000RPS -benchmem ./internal/detector/...
```

### Build & Pack Locally

```bash
# Build all 3 Go binaries + Vue 3 webapp, lint, sign (using ~/.nginx-ui-keys/signing.key), and generate .sha256
./build.sh

# Also run official conformance tests before packing
./build.sh --conformance

# Build only without packaging
./build.sh --no-pack
```

### Automated Releases

Pushing a version tag matching `plugin.json` (for example `v0.1.5`) triggers [.github/workflows/release.yml](.github/workflows/release.yml), which runs all tests, builds all platforms, executes `nginx-ui plugin lint` & `conformance`, signs the archive with `PLUGIN_SIGNING_KEY`, and publishes the GitHub Release.

## License

[MIT](LICENSE)
