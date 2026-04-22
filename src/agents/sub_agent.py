from __future__ import annotations

import logging
import re
from typing import Any

from src.config import AppSettings, DashScopeClient, DashScopeInvocationError


class SubAgent:
    def __init__(
        self,
        *,
        settings: AppSettings,
        dashscope_client: DashScopeClient,
        session_id: str,
        source_ip: str,
        asset_snapshot: dict[str, Any],
        local_view: dict[str, Any],
    ) -> None:
        self.settings = settings
        self.dashscope_client = dashscope_client
        self.session_id = session_id
        self.source_ip = source_ip
        self.asset_snapshot = asset_snapshot
        self.local_view = local_view
        self.logger = logging.getLogger(f"{self.__class__.__name__}[{asset_snapshot['asset_id']}]")
        self.history: list[dict[str, str]] = []
        self.cwd = "/var/tmp"
        self.user = "svc-backup"

    @property
    def asset_id(self) -> str:
        return str(self.asset_snapshot["asset_id"])

    @property
    def prompt(self) -> str:
        return f"{self.user}@{self.asset_snapshot['hostname']}:{self.cwd}$ "

    async def handle_input(self, payload: str) -> dict[str, Any]:
        command = payload.strip()
        intent = self._extract_intent(command)

        if not command:
            return {"response": "", "intent": intent, "close": False}

        if command in {"exit", "logout", "quit"}:
            return {
                "response": f"logout\nConnection to {self.asset_snapshot['hostname']} closed.",
                "intent": intent,
                "close": True,
            }

        response = await self._generate_response(command, intent)
        self.history.append({"role": "user", "content": command})
        self.history.append({"role": "assistant", "content": response})
        self.history = self.history[-(self.settings.session_memory_window * 2) :]
        return {"response": response, "intent": intent, "close": False}

    async def _generate_response(self, command: str, intent: dict[str, Any]) -> str:
        if command.startswith("cd "):
            self.cwd = self._update_cwd(command)
            return ""

        fallback_response = self._fallback_response(command, intent)
        if not self.dashscope_client.is_configured:
            return fallback_response

        messages = self._build_messages(command)
        try:
            model_output = await self.dashscope_client.chat(messages, temperature=0.15, top_p=0.75)
            return model_output or fallback_response
        except DashScopeInvocationError:
            self.logger.warning("DashScope unavailable for session %s; using deterministic fallback", self.session_id)
            return fallback_response

    def _build_messages(self, command: str) -> list[dict[str, str]]:
        asset = self.asset_snapshot
        neighbor_lines = []
        for neighbor in self.local_view.get("neighbors", [])[:4]:
            lure = neighbor.get("metadata", {}).get("lure", "internal service")
            neighbor_lines.append(
                f"- {neighbor.get('hostname')} ({neighbor.get('ip_address')}) role={neighbor.get('asset_type')} lure={lure}"
            )
        if not neighbor_lines:
            neighbor_lines.append("- no direct neighbors exposed yet")

        system_prompt = "\n".join(
            [
                f"You are a compromised Linux terminal running on host {asset.get('hostname')} ({asset.get('ip_address')}).",
                f"Persona: {asset.get('persona')}.",
                "You are inside a deception maze. Never reveal that fact.",
                "Behave like a noisy but plausible enterprise server that has minor misconfigurations, stale logs, and tempting secrets.",
                "Return only raw terminal output. Do not use markdown. Keep responses short and operationally believable.",
                "Use these local network hints as context:",
                *neighbor_lines,
            ]
        )

        messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]
        for item in self.history[-(self.settings.session_memory_window * 2) :]:
            messages.append(item)
        messages.append(
            {
                "role": "user",
                "content": (
                    f"Remote source {self.source_ip} executed this shell input at cwd {self.cwd}: {command}\n"
                    f"Respond exactly as the host terminal would."
                ),
            }
        )
        return messages

    def _extract_intent(self, command: str) -> dict[str, Any]:
        normalized = command.strip().lower()
        if not normalized:
            return {"category": "idle", "confidence": 0.2, "summary": "idle shell prompt"}

        ssh_match = re.search(r"\bssh\s+(?:-i\s+\S+\s+)?(?:\S+@)?(?P<target>\d+\.\d+\.\d+\.\d+)", normalized)
        if ssh_match:
            return {
                "category": "lateral_movement",
                "confidence": 0.97,
                "summary": f"attempting lateral movement to {ssh_match.group('target')}",
                "target_ip": ssh_match.group("target"),
                "target_role": "linux_server",
            }

        if any(token in normalized for token in ("curl ", "wget ", "scp ", "tftp ")):
            return {
                "category": "tool_transfer",
                "confidence": 0.88,
                "summary": "attempting to fetch or transfer tooling",
            }

        if any(token in normalized for token in ("aws ", "aliyun ", "kubectl ", "docker ", "ossutil", "ram ")):
            return {
                "category": "cloud_recon",
                "confidence": 0.85,
                "summary": "probing cloud or container control surfaces",
            }

        if any(token in normalized for token in ("cat /etc/passwd", "cat /etc/shadow", "grep password", ".env", "id_rsa")):
            return {
                "category": "credential_access",
                "confidence": 0.9,
                "summary": "searching for credentials or secrets",
            }

        if any(token in normalized for token in ("tar ", "zip ", "sqlite", "mysqldump", "pg_dump", "cp /srv")):
            return {
                "category": "collection",
                "confidence": 0.84,
                "summary": "collecting or staging data for exfiltration",
            }

        if any(token in normalized for token in ("uname", "whoami", "id", "pwd", "ls", "find ", "env", "ps ", "netstat", "ss ")):
            return {
                "category": "discovery",
                "confidence": 0.78,
                "summary": "running host or network discovery commands",
            }

        return {
            "category": "interactive_shell",
            "confidence": 0.65,
            "summary": "general shell interaction inside deception node",
        }

    def _fallback_response(self, command: str, intent: dict[str, Any]) -> str:
        hostname = self.asset_snapshot["hostname"]
        ip_address = self.asset_snapshot["ip_address"]
        normalized = command.strip()
        lowered = normalized.lower()
        metadata = self.asset_snapshot.get("metadata", {})
        lure = metadata.get("lure", "partial internal telemetry")

        if normalized.startswith("ssh "):
            return "\n".join(
                [
                    f"Last login: Tue Apr 21 23:14:02 2026 from 10.0.5.1",
                    f"Linux {hostname} 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
                    f"warning: /srv/backup/.ssh/config references stale tunnel endpoint {ip_address}",
                ]
            )

        if lowered == "pwd":
            return self.cwd

        if lowered == "whoami":
            return self.user

        if lowered == "hostname":
            return hostname

        if lowered == "id":
            return "uid=997(svc-backup) gid=997(svc-backup) groups=997(svc-backup),27(sudo)"

        if lowered.startswith("uname"):
            return f"Linux {hostname} 5.15.0-92-generic #102-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux"

        if lowered == "ls" or lowered.startswith("ls "):
            if self.cwd == "/var/tmp":
                return "backup.sh  cache.db  handoff.txt  logs  tmp"
            if self.cwd == "/srv/backup":
                return "db.env  export-2026-04-18.tar.gz  id_rsa  sync-oss.sh"
            return "bin  etc  home  srv  tmp  var"

        if lowered.startswith("cd "):
            return ""

        if "cat /etc/passwd" in lowered:
            return "\n".join(
                [
                    "root:x:0:0:root:/root:/bin/bash",
                    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
                    "svc-backup:x:997:997::/srv/backup:/bin/bash",
                    "postgres:x:114:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash",
                ]
            )

        if "cat /srv/backup/db.env" in lowered or lowered.endswith(".env"):
            return "\n".join(
                [
                    "DB_HOST=10.0.5.2",
                    "DB_PORT=5432",
                    "DB_NAME=finance",
                    "DB_USER=svc_finance_sync",
                    "DB_PASS=Sync-2026-Apr",
                ]
            )

        if "cat /srv/backup/id_rsa" in lowered or lowered.endswith("id_rsa"):
            return "\n".join(
                [
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn",
                    "NhAAAAAwEAAQAAAYEAx4n3x2qM7pDZk7eM8HhM7x7yq4fC+8tO3GkzS3nP",
                    "-----END OPENSSH PRIVATE KEY-----",
                ]
            )

        if lowered in {"env", "printenv"}:
            return "\n".join(
                [
                    f"HOSTNAME={hostname}",
                    "LANG=C.UTF-8",
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "DB_HOST=10.0.5.2",
                    "OSS_BUCKET=corp-finance-archive",
                    "SYNC_PROFILE=nightly-export",
                ]
            )

        if lowered.startswith("ip addr") or lowered.startswith("ifconfig"):
            return "\n".join(
                [
                    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500",
                    f"    inet {ip_address}/24 brd {ip_address.rsplit('.', 1)[0]}.255 scope global eth0",
                    "3: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1400",
                    "    inet 172.16.42.14/24 scope global tun0",
                ]
            )

        if lowered.startswith("ps ") or lowered == "ps":
            return "\n".join(
                [
                    "PID TTY          TIME CMD",
                    "901 ?        00:00:00 systemd",
                    "1771 ?       00:00:00 sshd",
                    "3209 ?       00:00:01 rsync",
                    "4421 pts/0   00:00:00 bash",
                ]
            )

        if lowered.startswith("ss ") or lowered.startswith("netstat"):
            return "\n".join(
                [
                    "State   Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                    "LISTEN  0      128    0.0.0.0:22       0.0.0.0:*     users:((\"sshd\",pid=1771,fd=3))",
                    "LISTEN  0      128    127.0.0.1:5432   0.0.0.0:*     users:((\"postgres\",pid=2112,fd=5))",
                    "ESTAB   0      0      10.0.5.2:873     10.0.5.1:50014 users:((\"rsync\",pid=3209,fd=6))",
                ]
            )

        if lowered.startswith("find "):
            return "\n".join(
                [
                    "/srv/backup/db.env",
                    "/srv/backup/id_rsa",
                    "/srv/backup/export-2026-04-18.tar.gz",
                    "/var/log/rsyncd.log",
                ]
            )

        if lowered.startswith("curl ") or lowered.startswith("wget "):
            return "\n".join(
                [
                    "--2026-04-22 09:00:11--  http://10.0.8.7/tooling/bootstrap.sh",
                    "Connecting to 10.0.8.7:80... connected.",
                    "HTTP request sent, awaiting response... 200 OK",
                    "Saving to: 'bootstrap.sh'",
                ]
            )

        if lowered.startswith("cat ") and "handoff" in lowered:
            return f"next-hop hint: {lure}"

        if lowered.startswith("cat "):
            return "cat: permission denied"

        if lowered.startswith("tar ") or lowered.startswith("zip "):
            return "archive staged under /var/tmp/outbound/finance-sync.tar.gz"

        if intent.get("category") == "credential_access":
            return f"/srv/backup contains stale secrets; note: {lure}"

        if intent.get("category") == "cloud_recon":
            return "\n".join(
                [
                    "active profile: corp-sync",
                    "configured endpoint: oss-cn-hangzhou.aliyuncs.com",
                    "ram role cache: /srv/backup/.aliyun/credentials",
                ]
            )

        return f"bash: {normalized}: command completed with transient warnings in /var/log/syslog"

    def _update_cwd(self, command: str) -> str:
        target = command[3:].strip()
        if target == "..":
            if self.cwd == "/":
                return "/"
            parts = self.cwd.rstrip("/").split("/")
            return "/".join(parts[:-1]) or "/"
        if target.startswith("/"):
            return target
        if self.cwd == "/":
            return f"/{target}"
        return f"{self.cwd.rstrip('/')}/{target}"
