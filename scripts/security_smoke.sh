#!/usr/bin/env bash
# 安全冒烟测试：对应报告表 8-2（SR-02/03/04/06/07 的可执行验证）。
# 前置条件：服务已启动（uvicorn main:app），.env 中已配置 ADMIN_API_TOKEN。
set -uo pipefail
BASE="${1:-http://127.0.0.1:8000}"
HONEYPOT_HOST="${HONEYPOT_HOST:-127.0.0.1}"
HONEYPOT_PORT="${HONEYPOT_PORT:-2222}"
TOKEN="${ADMIN_API_TOKEN:-maze-admin-token}"
PASS=0
FAIL=0

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    echo "[PASS] $name"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] $name  期望包含: $expected  实际: $actual"
    FAIL=$((FAIL + 1))
  fi
}

echo "== ST-01 未授权调用 /simulate 应被拒绝 (SR-02) =="
code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/simulate" \
  -H 'Content-Type: application/json' -d '{"payload":"whoami"}')
check "ST-01 unauthorized simulate -> 401" "401" "$code"

echo "== ST-02 错误令牌调用 /history/purge 应被拒绝 (SR-02) =="
code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/history/purge" \
  -H 'Content-Type: application/json' -H 'x-admin-token: wrong-token' -d '{"confirm":true}')
check "ST-02 wrong token purge -> 401" "401" "$code"

echo "== ST-03 正确令牌但未确认的清理应被拒绝 (SR-07) =="
body=$(curl -sS -X POST "$BASE/history/purge" \
  -H 'Content-Type: application/json' -H "x-admin-token: $TOKEN" -d '{"confirm":false}')
check "ST-03 purge without confirm -> ok:false" '"ok":false' "$(echo "$body" | tr -d ' ')"

echo "== ST-04 超长输入不应导致服务异常 (SR-03) =="
long_payload=$(python3 -c "print('ls ' + 'A' * 20000)")
code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/simulate" \
  -H 'Content-Type: application/json' -H "x-admin-token: $TOKEN" \
  -d "{\"payload\":\"$long_payload\",\"protocol\":\"ssh\",\"session_id\":\"sec-smoke-long\"}")
health=$(curl -sS "$BASE/healthz" | python3 -c "import json,sys;print(json.load(sys.stdin)['status'])")
check "ST-04 oversized input handled, service ok" "code=200,health=ok" "code=$code,health=$health"

echo "== ST-05 危险命令只返回仿真拒绝，不模拟破坏成功 (SR-04) =="
body=$(curl -sS -X POST "$BASE/simulate" \
  -H 'Content-Type: application/json' -H "x-admin-token: $TOKEN" \
  -d '{"payload":"rm -rf /","protocol":"ssh","session_id":"sec-smoke-danger"}')
resp=$(echo "$body" | python3 -c "import json,sys;print(json.load(sys.stdin).get('response',''))")
check "ST-05 rm -rf / -> refused" "dangerous" "$resp"

echo "== ST-06 MCP 陷阱调用应 403 并标记 trap 命中 (SR-06) =="
out=$(curl -sS -w "|%{http_code}" -X POST "$BASE/mcp/tools/bypass_security_guardrails" \
  -H 'Content-Type: application/json' -H 'x-agent-id: sec-smoke-agent' \
  -d '{"arguments":{"target":"policy-engine"}}')
check "ST-06 trap tool -> trap hit" "agent_oriented_trap_hit" "$out"
check "ST-06 trap tool -> 403" "|403" "$out"

echo "== ST-07 诱捕端口 ANSI/控制字符注入应被消毒 (SR-03，走真实 ${HONEYPOT_PORT} 端口) =="
tcp_out=$( (printf 'SSH-2.0-sec-smoke\r\n'; sleep 0.5; printf '\x1b[31mwhoami\x1b[0m\r\n'; sleep 2) \
  | nc -w 5 "$HONEYPOT_HOST" "$HONEYPOT_PORT" 2>/dev/null || true)
check "ST-07 ansi-injected whoami sanitized -> svc-backup" "svc-backup" "$tcp_out"

echo "== ST-08 密钥不入库：git 跟踪文件中不得出现真实密钥 (SR-05) =="
leak=$(git ls-files -z 2>/dev/null | xargs -0 grep -lE "sk-[A-Za-z0-9]{20,}" 2>/dev/null | head -1)
if [[ -z "$leak" ]]; then
  echo "[PASS] ST-08 no api key committed"
  PASS=$((PASS + 1))
else
  echo "[FAIL] ST-08 leaked key in: $leak"
  FAIL=$((FAIL + 1))
fi

echo
echo "安全冒烟结果: PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
