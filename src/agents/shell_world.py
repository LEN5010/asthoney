"""会话内的虚拟主机。

常见命令只读写这一份世界。同一条 SSH 会话里 cd、touch 之后，下一条命令看得到。
模板来自资产类型，改动不会写回模板，也不会碰宿主机磁盘。
"""

from __future__ import annotations

import re
import shlex
from typing import Any


class ShellWorld:
    def __init__(
        self,
        *,
        asset_type: str,
        hostname: str,
        username: str,
        directories: dict[str, list[str]],
        files: dict[str, str],
        env_lines: list[str],
    ) -> None:
        self.asset_type = asset_type
        self.hostname = hostname
        self.username = username
        self.directories = {path: list(names) for path, names in directories.items()}
        self.files = dict(files)
        self.env_lines = list(env_lines)
        self.created: set[str] = set()
        self.planted: set[str] = set()
        self.cwd = "/var/tmp" if "/var/tmp" in self.directories else "/"

    def plant_clue(self, clue: str) -> None:
        """把规划员给出的路径放进世界。已有诱饵文件不覆盖。"""
        match = re.search(r"(/[\w./-]+)", clue or "")
        if not match:
            return
        path = match.group(1).rstrip("/") or "/"
        if path in self.files or path in self.directories:
            return
        self._add_file(path, clue.strip() + "\n", planted=True)

    def execute(self, command: str) -> str | None:
        """接管的命令返回输出。不接管时返回 None，交给后面的模型或其它仿真。"""
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        if not parts:
            return ""
        name = parts[0]
        args = [part for part in parts[1:] if not part.startswith("-")]
        if name == "pwd":
            return self.cwd
        if name == "whoami":
            return self.username
        if name == "hostname":
            return self.hostname
        if name == "id":
            return f"uid=997({self.username}) gid=997({self.username}) groups=997({self.username})"
        if name == "uname":
            return f"Linux {self.hostname} 5.15.0-92-generic #102-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux"
        if name in {"env", "printenv"}:
            return "\n".join(
                [
                    f"HOSTNAME={self.hostname}",
                    "LANG=C.UTF-8",
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    *self.env_lines,
                ]
            )
        if name == "cd":
            return self._cd(args[0] if args else "/")
        if name == "ls":
            return self._ls(args[-1] if args else self.cwd)
        if name == "cat":
            if not args:
                return "cat: missing operand"
            path = self.resolve(args[-1])
            if path in self.files or path in self.directories:
                return self._cat(path)
            return None
        if name == "find":
            root = args[-1] if args else self.cwd
            if root.startswith("-"):
                root = self.cwd
            path = self.resolve(root)
            found = self.files_under(path)
            if path in self.directories or found:
                return "\n".join(found)
            return f"find: '{root}': No such file or directory"
        if name == "mkdir":
            if not args:
                return "mkdir: missing operand"
            return self._mkdir(self.resolve(args[-1]))
        if name == "touch":
            if not args:
                return "touch: missing operand"
            return self._touch(self.resolve(args[-1]))
        if name == "rm":
            target = args[-1] if args else ""
            if not target:
                return "rm: missing operand"
            return f"rm: cannot remove '{target}': Permission denied"
        return None

    def snapshot(self) -> dict[str, Any]:
        files = []
        for path in sorted(self.files):
            files.append(
                {
                    "path": path,
                    "created": path in self.created,
                    "planted": path in self.planted,
                    "preview": self.files[path][:180],
                }
            )
        return {
            "available": True,
            "asset_type": self.asset_type,
            "hostname": self.hostname,
            "username": self.username,
            "cwd": self.cwd,
            "created": sorted(self.created),
            "planted": sorted(self.planted),
            "files": files,
        }

    def directory_map(self) -> dict[str, list[str]]:
        return {path: list(names) for path, names in self.directories.items()}

    def resolve(self, raw: str) -> str:
        text = raw.strip() or self.cwd
        if not text.startswith("/"):
            base = "" if self.cwd == "/" else self.cwd
            text = f"{base}/{text}"
        parts: list[str] = []
        for part in text.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts) if parts else "/"

    def files_under(self, root: str) -> list[str]:
        normalized = root.rstrip("/") or "/"
        if normalized not in self.directories and not any(
            path == normalized or path.startswith(normalized + "/") for path in self.directories
        ):
            if normalized not in self.files:
                return []
        found: list[str] = []
        for directory, names in self.directories.items():
            if directory != normalized and not directory.startswith(normalized + "/"):
                continue
            for name in names:
                found.append(f"/{name}" if directory == "/" else f"{directory}/{name}")
        return found

    def _cd(self, raw: str) -> str:
        path = self.resolve(raw)
        if path in self.directories:
            self.cwd = path
            return ""
        if self._is_listed(path) or path in self.files:
            return f"bash: cd: {raw}: Not a directory"
        return f"bash: cd: {raw}: No such file or directory"

    def _ls(self, raw: str) -> str:
        path = self.resolve(raw)
        if path in self.directories:
            return "  ".join(self.directories[path])
        if path in self.files or self._is_listed(path):
            return path.rsplit("/", 1)[-1]
        return f"ls: cannot access '{raw}': No such file or directory"

    def _is_listed(self, path: str) -> bool:
        parent, name = _split(path)
        return bool(name) and name in self.directories.get(parent, [])

    def _cat(self, path: str) -> str:
        if path in self.files:
            return self.files[path]
        if path in self.directories:
            return f"cat: {path}: Is a directory"
        return f"cat: {path}: No such file or directory"

    def _mkdir(self, path: str) -> str:
        if path in self.directories or path in self.files:
            return f"mkdir: cannot create directory '{path}': File exists"
        parent, name = _split(path)
        if parent not in self.directories:
            return f"mkdir: cannot create directory '{path}': No such file or directory"
        self.directories[path] = []
        if name not in self.directories[parent]:
            self.directories[parent].append(name)
        self.created.add(path)
        return ""

    def _touch(self, path: str) -> str:
        if path in self.directories:
            return ""
        if path in self.files:
            return ""
        parent, name = _split(path)
        if parent not in self.directories:
            return f"touch: cannot touch '{path}': No such file or directory"
        self._add_file(path, "", created=True)
        if name not in self.directories[parent]:
            self.directories[parent].append(name)
        return ""

    def _add_file(self, path: str, content: str, *, planted: bool = False, created: bool = False) -> None:
        parent, name = _split(path)
        if parent not in self.directories:
            self.directories.setdefault(parent, [])
            grand, parent_name = _split(parent)
            if grand in self.directories and parent_name not in self.directories[grand]:
                self.directories[grand].append(parent_name)
        if name and name not in self.directories[parent]:
            self.directories[parent].append(name)
        self.files[path] = content
        if planted:
            self.planted.add(path)
        if created:
            self.created.add(path)


def _split(path: str) -> tuple[str, str]:
    parent, _, name = path.rpartition("/")
    return (parent or "/"), name
