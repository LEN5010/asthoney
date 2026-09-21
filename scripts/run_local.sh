#!/usr/bin/env bash
# 本机演示启动：拉起 Neo4j，再启动控制面与诱捕入口。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "缺少 .env，请先复制 .env.example 并填写 NEO4J_PASSWORD 与 ADMIN_API_TOKEN"
  exit 1
fi

if command -v docker >/dev/null 2>&1; then
  docker compose up -d neo4j
else
  echo "未检测到 docker，假定本机 Neo4j 已在 bolt://127.0.0.1:7687 运行"
fi

echo "等待 Neo4j ..."
python3 - <<'PY'
import time, sys
try:
    from neo4j import GraphDatabase
except ImportError:
    sys.exit(0)

from pathlib import Path
values = {}
for line in Path(".env").read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    values[key.strip()] = value.strip()
uri = values.get("NEO4J_URI", "bolt://127.0.0.1:7687")
user = values.get("NEO4J_USER", "neo4j")
password = values.get("NEO4J_PASSWORD", "please_change_me")
for _ in range(30):
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            session.run("RETURN 1")
        driver.close()
        sys.exit(0)
    except Exception:
        time.sleep(2)
print("Neo4j 仍未就绪，请检查 docker compose logs neo4j", file=sys.stderr)
sys.exit(1)
PY

if [[ -x venv/bin/uvicorn ]]; then
  exec venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
fi
if [[ -x .venv/bin/uvicorn ]]; then
  exec .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
fi
exec uvicorn main:app --host 0.0.0.0 --port 8000
