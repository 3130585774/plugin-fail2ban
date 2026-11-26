# Nginx UI Fail2ban Guard (`plugin-fail2ban`)

Real-time Nginx access log intrusion detection and automated IP banning plugin for **Nginx UI v3**, built with `github.com/nginxui/plugin-sdk-go` and `@nginxui/plugin-sdk`.

## Highlights

- **Resident Go Server + gRPC `log.sink`**: Non-blocking 16,384-slot ingestion queue with immediate batch acknowledgment and `GOMEMLIMIT=100MiB` tuned for Linux cgroup v2 (`128 MiB`, no swap).
- **Bounded-Memory Detection Engine**: 64-shard LRU + 60-slot ring time buckets (default 50,000 tracked IPs) with 6 built-in jails:
  - `http-404-scan`: Deduplicated URI path 404 scanning with static asset exclusion (default `15/60s` -> `1h`).
  - `http-sensitive-probe`: Probes against `/.env`, `/.git/`, `/wp-login.php`, `/phpmyadmin`, etc. (default `3/5m` -> `24h`).
  - `http-auth-bruteforce`: Repeated `401`/`403` authentication failures (default `10/3m` -> `30m`).
  - `http-bad-bot`: Known scanner User-Agents (`sqlmap`, `nikto`, `zgrab`, `masscan`, `nuclei`, etc., default `2/60s` -> `24h`).
  - `nginxui-login-guard`: Protects Nginx UI admin login via host `auth.login_failed` events (default `5/10m` -> `1h`).
  - `recidive-escalation`: Escalates repeat offenders over a 7-day rolling window (`1h -> 24h -> 7d`).
- **Debounced Nginx Snippet Enforcer**: Coalesces rapid ban/unban bursts (3s debounce, 10s max wait), deduplicates via SHA-256, automatically shards under 256 KiB (up to 32 snippets), and enforces hardcoded anti-lockout rules (`127.0.0.0/8`, `::1`, `0.0.0.0/0`, `::/0`, and admin whitelist CIDRs).
- **Crash-Safe Storage & Privacy**: SQLite WAL ledger (`active_bans`, `ban_events`, `recidive_history`, `whitelist`, `jail_configs`) in `NGINX_UI_PLUGIN_DATA_DIR`, lightweight config in `host.kv`, and zero raw IP/URL/UA logging to `host.log` or `stderr`.
- **Vue 3 Console & Native Slots**: Standalone management console (Active Bans, Jail Rules, Whitelist & Setup Guide, Live WebSocket Events) plus `nginx_log.view:fail2ban`, `nginx_log.list.column:threat_hits`, and `site.log.actions` slots.

## Supported platforms

- `linux/amd64` (static Go binary, `CGO_ENABLED=0`)
- `linux/arm64` (static Go binary, `CGO_ENABLED=0`)
- `darwin/arm64` (local development / macOS Apple Silicon)

## Enabling Ban Enforcement in Nginx

Nginx UI keeps plugin snippets isolated and never auto-injects them into your site configs. After installing and enabling the plugin, add the include directive inside your `http {}` block (global) or target `server {}` block:

```nginx
include snippets/plugins/io.github.3130585774.fail2ban/fail2ban-bans.conf;
```

## Build & Verify

```bash
# Run Go unit tests, race detector, and throughput benchmark
go test -v -race ./...
go test -bench=BenchmarkDetector5000RPS -benchmem ./internal/detector/...

# Cross-compile Go binaries (linux-amd64, linux-arm64) & build Vue 3 webapp
chmod +x build.sh
./build.sh
```

## Official Nginx UI CLI Verification

On a machine with `nginx-ui` v3 installed:

```bash
nginx-ui plugin lint .
nginx-ui plugin conformance . --transport both
nginx-ui plugin pack . fail2ban-0.1.0.tar.gz
nginx-ui plugin install fail2ban-0.1.0.tar.gz --enable --approve-permissions
```

## License

MIT
