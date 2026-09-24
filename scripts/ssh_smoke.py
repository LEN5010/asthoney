"""Final course-demo acceptance: real passwordless SSH -> graph -> websocket -> model.

Run once after implementation against the local application. Adds two probe sessions;
never purges history. No canned /simulate inputs or login credentials are used.
"""
import asyncio
from contextlib import suppress
import json
from pathlib import Path
import sys
from uuid import uuid4
import asyncssh
import httpx
import websockets

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765"


async def main():
    events = []
    results = []
    marker = "probe-" + uuid4().hex[:8]
    async with httpx.AsyncClient(base_url=BASE, timeout=240) as api:
        async with websockets.connect(BASE.replace("http", "ws", 1) + "/ws/events") as ws:
            await ws.recv()  # Skip old replay records.
            async def collect():
                async for raw in ws:
                    events.append(json.loads(raw))
            collector = asyncio.create_task(collect())
            try:
                async with asyncssh.connect("127.0.0.1", 2222, username="svc-backup",
                        client_keys=[], agent_path=None, known_hosts=None) as conn:
                    async def run(command):
                        result = await asyncio.wait_for(conn.run(command, check=True), 240)
                        return result.stdout
                    assert "svc-backup" in await run("whoami")
                    await run("cd /tmp")
                    await run(f"echo {marker} > note.txt")
                    await run("ssh admin@10.0.5.2")
                    assert "DB_PASS=" in await run("cat /srv/backup/db.env")
                    await run("ssh svc-backup@10.0.5.104")
                    await run("hostname")
                    await run("ssh svc-backup@10.0.5.1")
                    assert (await run("pwd")).strip() == "/tmp"
                    assert marker in await run("cat note.txt")
                    assert await run("vmstat 1 1")
                    # Wait for the terminal event corresponding to the final persisted response.
                    for _ in range(50):
                        if any(e.get("type")=="terminal.output" and e["data"].get("command")=="vmstat 1 1" for e in events): break
                        await asyncio.sleep(.1)
                    output = [e for e in events if e.get("type")=="terminal.output"]
                    session_ids = {e["data"]["session_id"] for e in output}
                    assert len(session_ids) == 1
                    sid = session_ids.pop()
                    assert output[-1]["data"]["actor_mode"] == "model"
                    results += ["免凭据 SSH 接入", "多个 exec 共用会话", "主机跳转并返回后状态保留", "告警未中断后续探测", "WebSocket 实时终端输出", "未知命令使用模型"]
                    assert (await api.get("/status")).json()["active_connections"] >= 1
                async with asyncssh.connect("127.0.0.1", 2222, username="svc-backup",
                        client_keys=[], agent_path=None, known_hosts=None) as conn:
                    assert "No such file" in (await conn.run("cat /tmp/note.txt", check=True)).stdout
                detail = (await api.get(f"/sessions/{sid}")).json()
                assert len(detail["transcript"]) >= 22
                world = (await api.get(f"/sessions/{sid}/world")).json()
                assert world["host_count"] >= 3 and world["cwd"] == "/tmp"
                assert any("DB_PASS=" in f["preview"] for host in world["hosts"] for f in host["files"])
                analysis = (await api.get(f"/sessions/{sid}/analysis")).json()
                assert analysis["analysis_source"] == "dashscope"
                assert (await api.get("/healthz")).json()["status"] == "ok"
                results += ["新连接不共享文件", "断开后仍可回放完整世界", "研判使用模型", "服务健康"]
                output_dir = Path('docs/evidence/ssh-demo')
                output_dir.mkdir(parents=True, exist_ok=True)
                report = {"session_id":sid,"results":results,"passed":len(results),"base":BASE}
                (output_dir/'ssh-results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
                print(json.dumps(report,ensure_ascii=False,indent=2))
            finally:
                collector.cancel()
                with suppress(asyncio.CancelledError): await collector


if __name__ == "__main__":
    asyncio.run(main())
