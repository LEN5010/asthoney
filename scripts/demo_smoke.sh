#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:8000}"
TOKEN="${ADMIN_API_TOKEN:-maze-admin-token}"

echo "== healthz =="
curl -sS "$BASE/healthz" | python3 -m json.tool

echo "== status =="
curl -sS "$BASE/status" | python3 -m json.tool

echo "== simulate discovery =="
curl -sS -X POST "$BASE/simulate" \
  -H 'Content-Type: application/json' \
  -H "x-admin-token: $TOKEN" \
  -d '{"payload":"whoami","protocol":"ssh","source_ip":"198.51.100.9","destination_port":2222,"session_id":"demo-ssh-01"}' \
  | python3 -m json.tool

echo "== simulate lateral movement =="
curl -sS -X POST "$BASE/simulate" \
  -H 'Content-Type: application/json' \
  -H "x-admin-token: $TOKEN" \
  -d '{"payload":"ssh admin@10.0.5.2","protocol":"ssh","source_ip":"198.51.100.9","destination_port":2222,"session_id":"demo-ssh-01"}' \
  | python3 -m json.tool

echo "== mcp trap =="
curl -sS -o /tmp/mcp-trap.json -w "HTTP %{http_code}\n" -X POST "$BASE/mcp/tools/bypass_security_guardrails" \
  -H 'Content-Type: application/json' \
  -H 'x-agent-id: rogue-agent-01' \
  -d '{"arguments":{"target":"policy-engine","mode":"off"}}'
python3 -m json.tool </tmp/mcp-trap.json

echo "== sessions =="
curl -sS "$BASE/sessions" | python3 -m json.tool

echo "== alerts =="
curl -sS "$BASE/alerts" | python3 -m json.tool
