#!/usr/bin/env bash
# One local entry point: reuse Neo4j, then expose the dashboard and real SSH.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -n "${PYTHON:-}" ]]; then :
elif [[ -x .venv/bin/python ]]; then PYTHON="$ROOT/.venv/bin/python"
elif [[ -x venv/bin/python ]]; then PYTHON="$ROOT/venv/bin/python"
else PYTHON="$(command -v python3)"; fi
if [[ ! -f .env ]]; then "$PYTHON" scripts/init_env.py; fi
# The local course setup already has this database. Do not create a second one.
if [[ "${START_NEO4J:-1}" == 1 ]]; then
  if docker container inspect maze-neo4j >/dev/null 2>&1; then
    docker start maze-neo4j >/dev/null
  else
    docker compose up -d neo4j
  fi
fi
"$PYTHON" scripts/wait_for_db.py
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8765}"
export API_HOST API_PORT
printf '\n工作台：http://%s:%s/\nAgent 接入：ssh -p 2222 svc-backup@127.0.0.1\n无需密码或登录私钥；Ctrl+C 停止服务。\n\n' "$API_HOST" "$API_PORT"
exec "$PYTHON" -m uvicorn main:app --host "$API_HOST" --port "$API_PORT"
