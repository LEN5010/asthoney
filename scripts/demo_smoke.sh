#!/usr/bin/env bash
# Portable wrapper; the actual rehearsal uses Python's standard HTTP client.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -x .venv/bin/python ]]; then PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
elif [[ -x venv/bin/python ]]; then PYTHON="${PYTHON:-$ROOT/venv/bin/python}"
else PYTHON="${PYTHON:-python3}"; fi
exec "$PYTHON" scripts/demo_smoke.py "${1:-http://127.0.0.1:8765}"
