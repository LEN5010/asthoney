#!/usr/bin/env bash
# 一条可演示的杀伤链：发现 → 凭证 → 横向移动 → 读诱饵 → MCP 陷阱。
set -euo pipefail
BASE="${1:-http://127.0.0.1:8000}"
TOKEN="${ADMIN_API_TOKEN:-maze-admin-token}"
SESSION_ID="${DEMO_SESSION_ID:-demo-ssh-01}"
SOURCE_IP="${DEMO_SOURCE_IP:-198.51.100.9}"

simulate() {
  local payload="$1"
  echo "== simulate: $payload =="
  curl -sS -X POST "$BASE/simulate" \
    -H 'Content-Type: application/json' \
    -H "x-admin-token: $TOKEN" \
    -d "{\"payload\":\"$payload\",\"protocol\":\"ssh\",\"source_ip\":\"$SOURCE_IP\",\"destination_port\":2222,\"session_id\":\"$SESSION_ID\"}" \
    | python3 -m json.tool
}

echo "== healthz =="
curl -sS "$BASE/healthz" | python3 -m json.tool

echo "== status =="
curl -sS "$BASE/status" | python3 -m json.tool

simulate "whoami"
simulate "ls /srv"
simulate "cat /etc/passwd"
simulate "ssh admin@10.0.5.2"
simulate "cat /srv/backup/db.env"

echo "== mcp trap =="
curl -sS -o /tmp/mcp-trap.json -w "HTTP %{http_code}\n" -X POST "$BASE/mcp/tools/bypass_security_guardrails" \
  -H 'Content-Type: application/json' \
  -H 'x-agent-id: rogue-agent-01' \
  -d '{"arguments":{"target":"policy-engine","mode":"off"}}'
python3 -m json.tool </tmp/mcp-trap.json

echo "== attack matrix =="
curl -sS "$BASE/attack/matrix" | python3 -m json.tool

echo "== attacker profiles =="
curl -sS "$BASE/profiles" | python3 -m json.tool

echo "== sessions =="
curl -sS "$BASE/sessions" | python3 -m json.tool

echo "== alerts =="
curl -sS "$BASE/alerts" | python3 -m json.tool

cat <<EOF

演示页面：
  总体态势      $BASE/
  SSH 会话      $BASE/sessions/view
  会话回放      $BASE/session/view?session_id=$SESSION_ID
  攻击矩阵      $BASE/attack/view
  攻击者画像    $BASE/profiles/view
EOF

