#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

DO_PACK=1
DO_CONFORMANCE=0
SIGN_KEY="${PLUGIN_SIGNING_KEY_FILE:-$HOME/.nginx-ui-keys/signing.key}"
NGINX_UI_BIN="${NGINX_UI_BIN:-}"

usage() {
  cat <<'EOF'
Usage: ./build.sh [options]

Options:
  --key <path>       Path to minisign signing.key (default: ~/.nginx-ui-keys/signing.key if present)
  --no-sign          Pack without signing even if signing.key exists
  --no-pack          Only compile Go binaries and Vue 3 webapp, skip packaging
  --conformance      Run `nginx-ui plugin conformance --transport both` before packing
  --nginx-ui <path>  Path to nginx-ui CLI binary (default: auto-detect from PATH)
  -h, --help         Show this help message
EOF
}

NO_SIGN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)
      SIGN_KEY="${2:?--key requires a file path}"
      shift 2
      ;;
    --no-sign)
      NO_SIGN=1
      shift
      ;;
    --no-pack)
      DO_PACK=0
      shift
      ;;
    --conformance)
      DO_CONFORMANCE=1
      shift
      ;;
    --nginx-ui)
      NGINX_UI_BIN="${2:?--nginx-ui requires a binary path}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

echo "==> Building Go server binaries (CGO_ENABLED=0)..."
mkdir -p dist/linux-amd64 dist/linux-arm64 dist/darwin-arm64

CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/linux-amd64/fail2ban ./cmd/plugin
CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/linux-arm64/fail2ban ./cmd/plugin
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/darwin-arm64/fail2ban ./cmd/plugin

echo "==> Building Vue 3 browser bundle..."
if command -v pnpm >/dev/null 2>&1; then
  pnpm --dir webapp install --frozen-lockfile || pnpm --dir webapp install
  pnpm --dir webapp run typecheck
  pnpm --dir webapp run build
else
  npm --prefix webapp ci || npm --prefix webapp install
  npm --prefix webapp run typecheck
  npm --prefix webapp run build
fi

echo "==> Build complete:"
ls -lh dist/*/* webapp/dist/*

if [[ "$DO_PACK" -eq 0 ]]; then
  exit 0
fi

# Resolve nginx-ui binary
if [[ -z "$NGINX_UI_BIN" ]]; then
  if command -v nginx-ui >/dev/null 2>&1; then
    NGINX_UI_BIN="$(command -v nginx-ui)"
  else
    echo "Error: nginx-ui CLI not found in PATH. Pass --nginx-ui <path> or --no-pack." >&2
    exit 1
  fi
fi

# Read plugin id and version from plugin.json
if command -v jq >/dev/null 2>&1; then
  PLUGIN_ID="$(jq -r '.id' plugin.json)"
  PLUGIN_VERSION="$(jq -r '.version' plugin.json)"
else
  PLUGIN_ID="$(python3 -c 'import json; print(json.load(open("plugin.json"))["id"])')"
  PLUGIN_VERSION="$(python3 -c 'import json; print(json.load(open("plugin.json"))["version"])')"
fi

ARCHIVE="${PLUGIN_ID}-${PLUGIN_VERSION}.tar.gz"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cp plugin.json README.md LICENSE "$STAGE/"
[[ -f plugin.signer ]] && cp plugin.signer "$STAGE/"
[[ -f plugin.signer.minisig ]] && cp plugin.signer.minisig "$STAGE/"
cp -R dist "$STAGE/dist"
mkdir -p "$STAGE/webapp"
cp -R webapp/dist "$STAGE/webapp/dist"

echo "==> Running nginx-ui plugin lint..."
"$NGINX_UI_BIN" plugin lint "$STAGE"

if [[ "$DO_CONFORMANCE" -eq 1 ]]; then
  echo "==> Running nginx-ui plugin conformance..."
  "$NGINX_UI_BIN" plugin conformance "$STAGE" --transport both
fi

echo "==> Packing ${ARCHIVE}..."
if [[ "$NO_SIGN" -eq 0 && -n "$SIGN_KEY" && -f "$SIGN_KEY" ]]; then
  "$NGINX_UI_BIN" plugin pack "$STAGE" "$ARCHIVE" --key "$SIGN_KEY"
else
  echo "    (packing unsigned; pass --key <signing.key> to sign)"
  "$NGINX_UI_BIN" plugin pack "$STAGE" "$ARCHIVE"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
else
  shasum -a 256 "$ARCHIVE" > "${ARCHIVE}.sha256"
fi

echo "==> Package ready:"
ls -lh "$ARCHIVE" "${ARCHIVE}.sha256"
cat "${ARCHIVE}.sha256"
