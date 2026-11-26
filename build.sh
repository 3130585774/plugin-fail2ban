#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "==> Building Go server binaries (CGO_ENABLED=0)..."
mkdir -p dist/linux-amd64 dist/linux-arm64 dist/darwin-arm64

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/linux-amd64/fail2ban ./cmd/plugin
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/linux-arm64/fail2ban ./cmd/plugin
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/darwin-arm64/fail2ban ./cmd/plugin

echo "==> Building Vue 3 browser bundle..."
if command -v pnpm >/dev/null 2>&1; then
  pnpm --dir webapp install --frozen-lockfile || pnpm --dir webapp install
  pnpm --dir webapp build
else
  npm --prefix webapp ci || npm --prefix webapp install
  npm --prefix webapp run build
fi

echo "==> Build complete:"
ls -lh dist/*/* webapp/dist/*
