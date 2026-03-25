#!/bin/sh
set -eu

fix_dir() {
  p="$1"
  [ -n "${p:-}" ] || return 0
  d="$(dirname "$p")"
  mkdir -p "$d" 2>/dev/null || true
  chown -R nodejs:nodejs "$d" 2>/dev/null || true
}

# Ensure token/credentials directories are writable when mounted as volumes.
fix_dir "${GOOGLE_CALENDAR_MCP_TOKEN_PATH:-}"
fix_dir "${GOOGLE_OAUTH_CREDENTIALS:-}"

# Common default for Railway / container platforms that mount persistent storage at /mnt/auth
if [ -d "/mnt/auth" ]; then
  chown -R nodejs:nodejs /mnt/auth 2>/dev/null || true
fi

exec su-exec nodejs:nodejs "$@"

