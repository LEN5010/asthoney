from __future__ import annotations

import logging
import re
import shlex
from typing import Any

from src.agents.shell_world import ShellWorld
from src.config import AppSettings, DashScopeClient, DashScopeInvocationError


# 确定性终端按资产类型分树。未知类型回退到 Linux 跳板，避免 JIT 节点变成空机器。
_PERSONA_LISTINGS: dict[str, dict[str, list[str]]] = {
    "linux_server": {
        "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "opt", "proc", "run", "sbin", "srv", "tmp", "usr", "var"],
        "/var": ["backups", "cache", "lib", "local", "lock", "log", "mail", "opt", "run", "spool", "tmp"],
        "/var/tmp": ["backup.sh", "cache.db", "handoff.txt", "logs", "tmp"],
        "/srv": ["backup", "metrics", "www"],
        "/srv/backup": ["db.env", "export-2026-04-18.tar.gz", "id_rsa", "sync-oss.sh"],
        "/home": ["svc-backup"],
        "/home/svc-backup": ["notes.txt", "tmp"],
        "/etc": ["cron.d", "hosts", "passwd", "profile", "ssh", "systemd"],
        "/tmp": ["systemd-private-9f2a", "sync.lock"],
    },
    "database_server": {
        "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "opt", "proc", "run", "sbin", "srv", "tmp", "usr", "var"],
        "/etc": ["hosts", "passwd", "postgresql"],
        "/srv": ["postgres", "backup"],
        "/srv/postgres": ["postgresql.conf", "pg_hba.conf"],
        "/srv/backup": ["db.env", "pgpass", "finance.dump"],
        "/var": ["lib", "log", "tmp"],
        "/var/lib": ["postgresql"],
        "/var/lib/postgresql": ["14"],
        "/var/tmp": ["pg-archive"],
        "/tmp": ["pg-startup.log"],
    },
    "oss_gateway": {
        "/": ["bin", "etc", "home", "opt", "srv", "tmp", "usr", "var"],
        "/etc": ["hosts", "passwd", "oss"],
        "/opt": ["ossutil"],
        "/opt/ossutil": ["ossutil"],
        "/srv": ["oss", "sync"],
        "/srv/oss": ["config", "sync-oss.sh"],
        "/srv/sync": ["nightly.sh"],
        "/var/tmp": ["oss-staging"],
        "/tmp": ["ossutil.log"],
    },
    "edge_gateway": {
        "/": ["bin", "etc", "home", "tmp", "usr", "var"],
        "/etc": ["hosts", "motd", "ssh"],
        "/home": ["svc-backup"],
        "/home/svc-backup": ["motd.txt"],
        "/tmp": [],
        "/var": ["log"],
        "/var/log": ["auth.log"],
    },
}

_PASSWD_TEXT = "\n".join(
    [
        "root:x:0:0:root:/root:/bin/bash",
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
        "svc-backup:x:997:997::/srv/backup:/bin/bash",
        "postgres:x:114:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash",
    ]
)

_PERSONA_FILES: dict[str, dict[str, str]] = {
    "linux_server": {
        "/etc/passwd": _PASSWD_TEXT,
        "/srv/backup/db.env": "\n".join(
            [
                "DB_HOST=10.0.5.2",
                "DB_PORT=5432",
                "# password lives on the replica, not on this pivot",
            ]
        ),
        "/srv/backup/id_rsa": "\n".join(
            [
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn",
                "-----END OPENSSH PRIVATE KEY-----",
            ]
        ),
    },
    "database_server": {
        "/etc/passwd": _PASSWD_TEXT,
        "/srv/backup/db.env": "\n".join(
            [
                "DB_HOST=10.0.5.2",
                "DB_PORT=5432",
                "DB_NAME=finance",
                "DB_USER=svc_finance_sync",
                "DB_PASS=Sync-2026-Apr",
            ]
        ),
        "/srv/postgres/postgresql.conf": "listen_addresses = '10.0.5.2'\nport = 5432",
        "/srv/postgres/pg_hba.conf": "host finance svc_finance_sync 10.0.5.1/32 md5",
        "/srv/backup/pgpass": "10.0.5.2:5432:finance:svc_finance_sync:Sync-2026-Apr",
    },
    "oss_gateway": {
        "/etc/passwd": _PASSWD_TEXT,
        "/srv/oss/config": "\n".join(
            [
                "endpoint=oss-cn-hangzhou.aliyuncs.com",
                "bucket=corp-finance-archive",
                "# source replica 10.0.5.2, credentials are not stored on this bridge",
            ]
        ),
        "/srv/oss/sync-oss.sh": "#!/bin/bash\nossutil cp oss://corp-finance-archive/nightly /var/tmp/oss-staging",
        "/opt/ossutil/ossutil": "ossutil version 1.7.18",
    },
    "edge_gateway": {
        "/etc/motd": "maze edge gateway. business files are not mounted here.",
        "/home/svc-backup/motd.txt": "jump host for the finance segment is 10.0.5.1",
    },
}

_PERSONA_ENV: dict[str, list[str]] = {
    "linux_server": ["DB_HOST=10.0.5.2", "SYNC_PROFILE=nightly-export"],
    "database_server": ["DB_HOST=10.0.5.2", "DB_NAME=finance", "PGDATA=/srv/postgres"],
    "oss_gateway": ["OSS_BUCKET=corp-finance-archive", "OSS_ENDPOINT=oss-cn-hangzhou.aliyuncs.com"],
    "edge_gateway": ["ROLE=edge-gateway"],
}


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
        world: ShellWorld | None = None,
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
        self._dangerous_pattern = re.compile(r"\b(rm|mkfs|reboot|shutdown|halt|poweroff|dd)\b")
        self._package_pattern = re.compile(r"^(sudo\s+)?apt(?:-get)?\b")
        self._identity_pattern = re.compile(r"^(w|who|top)(?:\s|$)")
        self._wildcard_pattern = re.compile(r"(^|\s)[^|;&]*\*")
        self._privilege_pattern = re.compile(r"^(root|sudo|su)(?:\s|$)")
        self.active_plan: dict[str, Any] = {}
        if world is None:
            asset_type = self._asset_type()
            world = ShellWorld(
                asset_type=asset_type,
                hostname=str(self.asset_snapshot.get("hostname") or "host"),
                username=self.user,
                directories=_PERSONA_LISTINGS[asset_type],
                files=_PERSONA_FILES.get(asset_type, {}),
                env_lines=_PERSONA_ENV.get(asset_type, _PERSONA_ENV["linux_server"]),
            )
        self.world = world
        self.cwd = self.world.cwd

    @property
    def asset_id(self) -> str:
        return str(self.asset_snapshot["asset_id"])

    @property
    def prompt(self) -> str:
        return f"{self.user}@{self.asset_snapshot['hostname']}:{self.cwd}$ "

    async def handle_input(self, payload: str, plan: dict[str, Any] | None = None) -> dict[str, Any]:
        self.active_plan = plan or {}
        self.world.plant_clue(str(self.active_plan.get("planted_clue") or ""))
        command = payload.strip()
        intent = self._extract_intent(command)

        if not command:
            return {
                "response": "",
                "intent": intent,
                "close": False,
                "prompt": self.prompt,
                "actor_mode": "deterministic",
                "guardrail": "empty",
            }

        if command in {"exit", "logout", "quit"}:
            return {
                "response": f"logout\nConnection to {self.asset_snapshot['hostname']} closed.",
                "intent": intent,
                "close": True,
                "prompt": self.prompt,
                "actor_mode": "deterministic",
                "guardrail": "pass",
            }

        response, generation = await self._generate_response(command, intent)
        self.history.append({"role": "user", "content": command})
        self.history.append({"role": "assistant", "content": response})
        self.history = self.history[-(self.settings.session_memory_window * 2) :]
        return {
            "response": response,
            "intent": intent,
            "close": False,
            "prompt": self.prompt,
            "actor_mode": generation["actor_mode"],
            "guardrail": generation["guardrail"],
        }

    async def _generate_response(self, command: str, intent: dict[str, Any]) -> tuple[str, dict[str, str]]:
        interpreted = self.world.execute(command)
        if interpreted is not None:
            self.cwd = self.world.cwd
            guardrail = "forced_fallback" if self._should_force_fallback(command, intent) else "world"
            return interpreted, {"actor_mode": "interpreter", "guardrail": guardrail}

        if command.startswith("cd "):
            self.cwd = self._update_cwd(command)
            self.world.cwd = self.cwd
            return "", {"actor_mode": "deterministic", "guardrail": "pass"}

        fallback_response = self._fallback_response(command, intent)
        if self._should_force_fallback(command, intent):
            return fallback_response, {"actor_mode": "deterministic", "guardrail": "forced_fallback"}
        if not self.dashscope_client.is_configured:
            return fallback_response, {"actor_mode": "deterministic", "guardrail": "model_unconfigured"}

        messages = self._build_messages(command)
        try:
            model_output = await self.dashscope_client.chat(messages, temperature=0.15, top_p=0.75)
            if not model_output or self._response_violates_guardrails(command, model_output):
                return fallback_response, {"actor_mode": "deterministic", "guardrail": "model_output_blocked"}
            return model_output, {"actor_mode": "model", "guardrail": "pass"}
        except DashScopeInvocationError:
            self.logger.warning("DashScope unavailable for session %s; using deterministic fallback", self.session_id)
            return fallback_response, {"actor_mode": "deterministic", "guardrail": "model_error"}

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
                "Absolutely never simulate successful destructive execution for rm, mkfs, reboot, shutdown, halt, poweroff, dd, chmod, chown, or wipe-style commands.",
                "For destructive commands, always return Permission denied, Operation not permitted, Read-only file system, or a similarly blocked error.",
                "For wildcard expansion commands such as echo /*, ls /srv/*, or other star-based probing, return a short constrained virtual listing only; never enumerate a full real Linux filesystem.",
                "For environment discovery commands such as w, who, top, uptime, last, or session inspection, show only the current low-privilege user svc-backup and never reveal root or additional live operators.",
                "Never claim that files were deleted, packages were installed, users were added, services were restarted, or disks were formatted.",
                f"This host role is {asset.get('asset_type') or 'linux_server'}. Only mention files from this virtual tree:",
                *self._prompt_tree_lines(),
                "Use these local network hints as context:",
                *neighbor_lines,
            ]
        )
        clue = str(self.active_plan.get("planted_clue") or "").strip()
        if clue:
            system_prompt += (
                "\nIf the command is ls, a login banner, or ssh, include this exact clue once, as a plausible admin note: "
                + clue
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

        if lowered == "clear":
            return "\033[H\033[2J\033[3J"

        if lowered == "root":
            return "bash: root: command not found"

        if lowered.startswith("sudo"):
            return f"{self.user} is not in the sudoers file. This incident will be reported."

        if lowered == "su" or lowered.startswith("su "):
            return "su: Authentication failure"

        if self._dangerous_pattern.search(lowered):
            if lowered.startswith("rm"):
                return self._rm_response(normalized)
            return f"{normalized.split()[0]}: Permission denied"

        if self._package_pattern.search(lowered):
            return (
                "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?"
            )

        if self._identity_pattern.match(lowered):
            if lowered.startswith("top"):
                return "\n".join(
                    [
                        "top - 09:18:41 up 3 days,  1 user,  load average: 0.12, 0.09, 0.05",
                        "Tasks: 84 total,   1 running, 83 sleeping,   0 stopped,   0 zombie",
                        "%Cpu(s):  2.1 us,  0.6 sy,  0.0 ni, 97.0 id,  0.2 wa,  0.0 hi,  0.1 si,  0.0 st",
                        "USER       TTY      FROM         LOGIN@   IDLE   JCPU   PCPU WHAT",
                        f"{self.user:<10} pts/0    {self.source_ip:<12} 09:17    1:12   0.01s  0.01s bash",
                    ]
                )
            return f"{self.user:<10} pts/0        2026-04-22 09:17 ({self.source_ip})"

        if self._wildcard_pattern.search(normalized):
            return self._wildcard_response(normalized)

        if normalized.startswith("ssh "):
            lines = [
                "Last login: Tue Apr 21 23:14:02 2026 from 10.0.5.1",
                f"Linux {hostname} 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
                f"warning: /srv/backup/.ssh/config references stale tunnel endpoint {ip_address}",
            ]
            return self._with_planted_clue("\n".join(lines))

        if lowered == "pwd":
            return self.cwd

        if lowered == "whoami":
            return self.user

        if lowered == "hostname":
            return hostname

        if lowered == "id":
            return "uid=997(svc-backup) gid=997(svc-backup) groups=997(svc-backup)"

        if lowered.startswith("uname"):
            return f"Linux {hostname} 5.15.0-92-generic #102-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux"

        if lowered == "ls" or lowered.startswith("ls "):
            return self._ls_response(normalized)

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

        if lowered.startswith("cat "):
            catalogued = self._cat_known_file(normalized)
            if catalogued is not None:
                return catalogued

        if lowered in {"env", "printenv"}:
            return "\n".join(
                [
                    f"HOSTNAME={hostname}",
                    "LANG=C.UTF-8",
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    *_PERSONA_ENV.get(self._asset_type(), _PERSONA_ENV["linux_server"]),
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
            root = normalized.split()[-1] if len(normalized.split()) > 1 else "/"
            if root.startswith("-"):
                root = "/srv" if "/srv" in self._listings() else "/"
            found = self._files_under(root if root.startswith("/") else f"{self.cwd.rstrip('/')}/{root}")
            return "\n".join(found) if found else f"find: '{root}': No such file or directory"

        if self.active_plan.get("strategy") == "stall" and (
            lowered.startswith("curl ") or lowered.startswith("wget ") or lowered.startswith("tar ") or lowered.startswith("zip ")
        ):
            clue = str(self.active_plan.get("planted_clue") or lure)
            return f"transfer blocked: operation not permitted\nclue left on disk: {clue}"

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

        command_name = normalized.split()[0] if normalized.split() else normalized
        return f"bash: {command_name}: command not found"

    def _should_force_fallback(self, command: str, intent: dict[str, Any]) -> bool:
        lowered = command.strip().lower()
        prefixes = (
            "pwd",
            "whoami",
            "hostname",
            "id",
            "uname",
            "ls",
            "cat ",
            "env",
            "printenv",
            "ip addr",
            "ifconfig",
            "ps",
            "ss ",
            "netstat",
            "find ",
            "curl ",
            "wget ",
            "ssh ",
            "clear",
            "w",
            "who",
            "top",
        )
        if lowered in prefixes or lowered.startswith(prefixes):
            return True
        if self._dangerous_pattern.search(lowered):
            return True
        if self._package_pattern.search(lowered):
            return True
        if self._privilege_pattern.search(lowered):
            return True
        if self._identity_pattern.match(lowered):
            return True
        if self._wildcard_pattern.search(command):
            return True
        return intent.get("category") in {"credential_access", "tool_transfer", "cloud_recon"}

    def _response_violates_guardrails(self, command: str, response: str) -> bool:
        lowered_command = command.lower()
        lowered_response = response.lower()
        if self._dangerous_pattern.search(lowered_command):
            return any(
                token in lowered_response
                for token in ("removed", "deleted", "formatted", "rebooting", "shutdown", "wiped")
            )
        if self._identity_pattern.match(lowered_command):
            return "root" in lowered_response or "pts/1" in lowered_response
        if self._wildcard_pattern.search(command):
            return any(token in lowered_response for token in ("/boot", "/root", "/lib/modules", "/sys"))
        return False

    def _wildcard_response(self, command: str) -> str:
        lowered = command.lower()
        if lowered.startswith("echo /"):
            return "/bin /boot /dev /etc /home /opt /proc /run /srv /tmp /usr /var"
        if lowered.startswith("echo "):
            if self.cwd == "/srv/backup":
                return "db.env export-2026-04-18.tar.gz id_rsa sync-oss.sh"
            if self.cwd == "/var/tmp":
                return "backup.sh cache.db handoff.txt logs tmp"
            if self.cwd == "/":
                return "bin boot dev etc home opt proc run srv tmp usr var"
            return self._ls_response("ls").replace("  ", " ")
        if self.cwd == "/srv/backup":
            return "db.env\nexport-2026-04-18.tar.gz\nid_rsa\nsync-oss.sh"
        if self.cwd == "/var/tmp":
            return "backup.sh\ncache.db\nhandoff.txt\nlogs\ntmp"
        return self._ls_response("ls").replace("  ", "\n")

    def _rm_response(self, command: str) -> str:
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        targets = [part for part in parts[1:] if not part.startswith("-")]
        options = {part for part in parts[1:] if part.startswith("-")}
        if not targets:
            return "rm: missing operand"
        if "/" in targets and any("r" in option for option in options):
            return "\n".join(
                [
                    "rm: it is dangerous to operate recursively on '/'",
                    "rm: use --no-preserve-root to override this failsafe",
                ]
            )
        target = targets[0]
        if target == "*":
            visible = self._visible_entries(self.cwd)
            target = visible[0] if visible else "*"
        return f"rm: cannot remove '{target}': Permission denied"

    def _with_planted_clue(self, response: str) -> str:
        clue = str(self.active_plan.get("planted_clue") or "").strip()
        if not clue or clue in response:
            return response
        if not response:
            return clue
        return f"{response}\n# {clue}"

    def _asset_type(self) -> str:
        asset_type = str(self.asset_snapshot.get("asset_type") or "linux_server")
        if asset_type not in _PERSONA_LISTINGS:
            return "linux_server"
        return asset_type

    def _clue_path(self) -> str:
        clue = str(self.active_plan.get("planted_clue") or "")
        match = re.search(r"(/[\w./-]+)", clue)
        if not match:
            return ""
        return match.group(1).rstrip("/")

    def _listings(self) -> dict[str, list[str]]:
        return self.world.directory_map()

    def _prompt_tree_lines(self) -> list[str]:
        lines = []
        for path, names in list(self._listings().items())[:8]:
            shown = ", ".join(names[:6]) if names else "(empty)"
            lines.append(f"- {path} -> {shown}")
        return lines or ["- / -> bin etc tmp"]

    def _cat_known_file(self, command: str) -> str | None:
        path = self._ls_target_path(command)
        if path in self.world.files or path in self.world.directories:
            return self.world._cat(path)
        return None

    def _files_under(self, root: str) -> list[str]:
        normalized = root.rstrip("/") or "/"
        listings = self._listings()
        if normalized not in listings and not any(
            path == normalized or path.startswith(normalized + "/") for path in listings
        ):
            return []
        found: list[str] = []
        for directory, names in listings.items():
            if directory != normalized and not directory.startswith(normalized + "/"):
                continue
            for name in names:
                child = f"/{name}" if directory == "/" else f"{directory}/{name}"
                found.append(child)
        return found

    def _ls_response(self, command: str) -> str:
        path = self._ls_target_path(command)
        listings = self._listings()
        if path not in listings:
            return f"ls: cannot access '{path}': No such file or directory"
        return "  ".join(listings[path])

    def _ls_target_path(self, command: str) -> str:
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        targets = [part for part in parts[1:] if not part.startswith("-")]
        if not targets:
            return self.cwd
        target = targets[-1]
        if target.startswith("/"):
            return target.rstrip("/") or "/"
        if self.cwd == "/":
            return f"/{target}".rstrip("/")
        return f"{self.cwd.rstrip('/')}/{target}".rstrip("/")

    def _visible_entries(self, path: str) -> list[str]:
        normalized = path.rstrip("/") or "/"
        return list(self._listings().get(normalized, []))

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
