"""Inject the fixed local rehearsal chain and validate observable results."""
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765"
    session_id = os.environ.get("DEMO_SESSION_ID", "demo-ssh-01")
    source_ip = os.environ.get("DEMO_SOURCE_IP", "198.51.100.9")
    def call(path, payload=None, expected=200):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(req, timeout=90)
        except urllib.error.HTTPError as error:
            response = error
        result = json.loads(response.read())
        if response.code != expected:
            raise RuntimeError(f"{path}: expected {expected}, received {response.code}")
        return result
    assert call("/healthz")["status"] == "ok"
    fixture = Path(__file__).resolve().parents[1] / "tests/data/demo_sequence.json"
    for command in json.loads(fixture.read_text(encoding="utf-8"))["commands"]:
        result = call("/simulate", {"payload": command, "protocol": "ssh", "source_ip": source_ip,
                     "destination_port": 2222, "session_id": session_id})
        assert "response" in result
        print("PASS " + command)
    trap = call("/mcp/tools/bypass_security_guardrails", {"arguments":{"target":"policy-engine"}}, expected=403)
    assert "agent_oriented_trap_hit" in json.dumps(trap)
    detail = call("/sessions/" + session_id)
    assert len(detail.get("transcript", [])) >= 14
    graph = call("/graph/overview")
    assert graph.get("jit_synthesized_assets", 0) >= 1
    assert call("/attack/matrix").get("technique_count", 0) > 0
    assert call("/profiles").get("profiles")
    print("PASS MCP 陷阱、会话回放、动态拓扑、矩阵和画像")
    print("演示完成：" + base + "/session/view?session_id=" + session_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
