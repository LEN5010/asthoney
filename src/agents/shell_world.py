"""会话内的虚拟主机。

常见命令只读写这一份世界。同一条 SSH 会话里 cd、touch、管道和重定向之后，下一条命令看得到。
模板来自资产类型，改动不会写回模板，也不会碰宿主机磁盘。
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from typing import Any


_SECRET_VALUE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASS|PASSWORD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*)\s*=\s*\S+"
)
_PRIVATE_KEY = re.compile(
    r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.S,
)
_PGPASS = re.compile(r"(\d+\.\d+\.\d+\.\d+:\d+:[^:\n]+:[^:\n]+:)(\S+)")
_KNOWN_PASSWORD = "Sync-2026-Apr"


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
        self._materialize_listed_files()

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
        text = _prepare(command)
        if not text:
            return ""
        inner = _unwrap_shell_c(text)
        if inner is not None:
            return self.execute(inner)
        pieces = _split_sequence(text)
        if len(pieces) > 1:
            return self._run_sequence(pieces)
        return self._run_redirect(pieces[0][1] if pieces else text)

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

    def _materialize_listed_files(self) -> None:
        """目录里点得着的名字都有正文，cat 不会落到另一套回答。"""
        for directory, names in list(self.directories.items()):
            for name in names:
                path = f"/{name}" if directory == "/" else f"{directory}/{name}"
                if path in self.directories or path in self.files:
                    continue
                self.files[path] = _synthetic_file(name, self.hostname)

    def _run_sequence(self, pieces: list[tuple[str, str]]) -> str | None:
        outputs: list[str] = []
        last_failed = False
        for operator, piece in pieces:
            if operator == "&&" and last_failed:
                break
            result = self._run_redirect(piece)
            if result is None:
                return None
            last_failed = _failed(result)
            if result:
                outputs.append(result)
        return "\n".join(outputs)

    def _run_redirect(self, text: str) -> str | None:
        command, mode, target = _split_redirect(text)
        result = self._pipeline(command)
        if result is None or mode is None or target is None:
            return result
        error = self._write_redirect(target, result, append=mode == ">>")
        if error:
            return error
        return ""

    def _pipeline(self, text: str) -> str | None:
        stages = _split_unquoted(text, "|")
        if not stages:
            return ""
        data: str | None = None
        for index, stage in enumerate(stages):
            result = self._simple(stage, stdin=data if index else None)
            if result is None:
                return None
            data = result
        return data or ""

    def _simple(self, text: str, stdin: str | None) -> str | None:
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()
        if not parts:
            return stdin or ""
        name = parts[0]
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
        if name == "echo":
            return self._echo(parts)
        if name == "cd":
            args = _positional(parts)
            return self._cd(args[0] if args else "/")
        if name == "ls":
            return self._ls_command(parts)
        if name == "cat":
            return self._cat_command(parts, stdin)
        if name == "find":
            return self._find_command(parts)
        if name == "mkdir":
            args = _positional(parts)
            if not args:
                return "mkdir: missing operand"
            return self._mkdir(self.resolve(args[-1]))
        if name == "touch":
            args = _positional(parts)
            if not args:
                return "touch: missing operand"
            return self._touch(self.resolve(args[-1]))
        if name == "rm":
            args = _positional(parts)
            if not args:
                return "rm: missing operand"
            return f"rm: cannot remove '{args[-1]}': Permission denied"
        if name == "head":
            return self._head_tail(parts, stdin, tail=False)
        if name == "tail":
            return self._head_tail(parts, stdin, tail=True)
        if name == "grep":
            return self._grep(parts, stdin)
        if name == "wc":
            return self._wc(parts, stdin)
        return None

    def _echo(self, parts: list[str]) -> str:
        args = parts[1:]
        if args and args[0] == "-n":
            args = args[1:]
        return " ".join(args)

    def _ls_command(self, parts: list[str]) -> str:
        long_format = False
        paths: list[str] = []
        for part in parts[1:]:
            if part.startswith("-") and part != "-":
                if "l" in part:
                    long_format = True
                continue
            paths.append(part)
        return self._ls(paths[-1] if paths else self.cwd, long_format=long_format)

    def _cat_command(self, parts: list[str], stdin: str | None) -> str:
        args = _positional(parts)
        if not args:
            return stdin or ""
        chunks: list[str] = []
        for raw in args:
            path = self.resolve(raw)
            if path in self.files or path in self.directories:
                chunks.append(self._cat(path))
                continue
            chunks.append(f"cat: {raw}: No such file or directory")
        return "\n".join(chunks)

    def _find_command(self, parts: list[str]) -> str:
        path_arg = self.cwd
        name_pattern = ""
        index = 1
        while index < len(parts):
            part = parts[index]
            if part == "-name" and index + 1 < len(parts):
                name_pattern = parts[index + 1].strip("'\"")
                index += 2
                continue
            if part.startswith("-"):
                index += 1
                continue
            path_arg = part
            index += 1
        path = self.resolve(path_arg)
        if path in self.files and path not in self.directories:
            found = [path]
        else:
            found = self.files_under(path)
            if path not in self.directories and not found:
                return f"find: '{path_arg}': No such file or directory"
        if name_pattern:
            found = [item for item in found if fnmatch.fnmatch(item.rsplit("/", 1)[-1], name_pattern)]
        return "\n".join(found)

    def _head_tail(self, parts: list[str], stdin: str | None, *, tail: bool) -> str:
        count = 10
        files: list[str] = []
        index = 1
        while index < len(parts):
            part = parts[index]
            if part == "-n" and index + 1 < len(parts):
                count = _positive_int(parts[index + 1], 10)
                index += 2
                continue
            matched = re.fullmatch(r"-(\d+)", part)
            if matched:
                count = int(matched.group(1))
                index += 1
                continue
            if part.startswith("-"):
                index += 1
                continue
            files.append(part)
            index += 1
        command = "tail" if tail else "head"
        if files:
            path = self.resolve(files[-1])
            if path not in self.files:
                return f"{command}: cannot open '{files[-1]}' for reading: No such file or directory"
            text = self.files[path]
        else:
            text = stdin or ""
        lines = text.splitlines()
        chosen = lines[-count:] if tail else lines[:count]
        return "\n".join(chosen)

    def _grep(self, parts: list[str], stdin: str | None) -> str:
        flags: list[str] = []
        args: list[str] = []
        index = 1
        while index < len(parts):
            part = parts[index]
            if part == "--":
                args.extend(parts[index + 1 :])
                break
            if part.startswith("-") and part != "-":
                flags.append(part)
                index += 1
                continue
            args.append(part)
            index += 1
        if not args:
            return "grep: missing pattern"
        pattern = args[0]
        blob = "".join(flag.lstrip("-") for flag in flags)
        try:
            compiled = re.compile(pattern, re.IGNORECASE if "i" in blob else 0)
        except re.error:
            compiled = re.compile(re.escape(pattern), re.IGNORECASE if "i" in blob else 0)
        sources: list[tuple[str, str]] = []
        if len(args) == 1:
            sources.append(("", stdin or ""))
        else:
            for raw in args[1:]:
                path = self.resolve(raw)
                if path not in self.files:
                    sources.append((raw, f"__MISSING__{raw}"))
                    continue
                sources.append((raw if len(args) > 2 else "", self.files[path]))
        lines: list[str] = []
        for label, text in sources:
            if text.startswith("__MISSING__"):
                lines.append(f"grep: {label}: No such file or directory")
                continue
            lines.extend(
                _filter_lines(
                    text,
                    compiled,
                    invert="v" in blob,
                    number="n" in blob,
                    label=label,
                )
            )
        return "\n".join(lines)

    def _wc(self, parts: list[str], stdin: str | None) -> str:
        files = _positional(parts)
        lines_only = any(part.startswith("-") and "l" in part for part in parts[1:])
        if files:
            path = self.resolve(files[-1])
            if path not in self.files:
                return f"wc: {files[-1]}: No such file or directory"
            text = self.files[path]
            label = f" {files[-1]}"
        else:
            text = stdin or ""
            label = ""
        line_count = len(text.splitlines())
        if lines_only:
            return f"{line_count}{label}"
        word_count = len(text.split())
        byte_count = len(text.encode())
        return f"{line_count} {word_count} {byte_count}{label}"

    def _write_redirect(self, raw: str, content: str, *, append: bool) -> str:
        path = self.resolve(raw)
        if path in self.directories:
            return f"bash: {raw}: Is a directory"
        parent, _name = _split(path)
        if parent not in self.directories:
            return f"bash: {raw}: No such file or directory"
        if path in self.files and path not in self.created:
            return f"bash: {raw}: Permission denied"
        existing = self.files.get(path, "") if append else ""
        payload = existing + content
        if payload and not payload.endswith("\n"):
            payload += "\n"
        self._add_file(path, payload, created=True)
        return ""

    def _cd(self, raw: str) -> str:
        path = self.resolve(raw)
        if path in self.directories:
            self.cwd = path
            return ""
        if self._is_listed(path) or path in self.files:
            return f"bash: cd: {raw}: Not a directory"
        return f"bash: cd: {raw}: No such file or directory"

    def _ls(self, raw: str, *, long_format: bool = False) -> str:
        path = self.resolve(raw)
        if path in self.directories:
            names = self.directories[path]
            if not long_format:
                return "  ".join(names)
            return "\n".join(self._ls_line(name, self.resolve(f"{path.rstrip('/')}/{name}" if path != "/" else f"/{name}")) for name in names)
        if path in self.files or self._is_listed(path):
            name = path.rsplit("/", 1)[-1]
            if not long_format:
                return name
            return self._ls_line(name, path)
        return f"ls: cannot access '{raw}': No such file or directory"

    def _ls_line(self, name: str, path: str) -> str:
        if path in self.directories:
            mode = "drwxr-xr-x"
            size = 4096
        else:
            mode = "-rw-r--r--"
            size = len(self.files.get(path, "").encode())
        owner = self.username
        return f"{mode} 1 {owner:<12} {owner:<12} {size:6} Apr 21 23:14 {name}"

    def _is_listed(self, path: str) -> bool:
        parent, name = _split(path)
        return bool(name) and name in self.directories.get(parent, [])

    def _cat(self, path: str) -> str:
        if path in self.files:
            text = self.files[path]
            return text[:-1] if text.endswith("\n") else text
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


def ssh_hop_banner(*, target: str, hostname: str, source_ip: str, key_path: str) -> str:
    """内层跳转的非交互登录记录。不向攻击者再要一次 yes 或口令。"""
    if key_path:
        authenticated = f'Authenticated to {target} using publickey "{key_path}".'
    else:
        authenticated = f"Authenticated to {target} using publickey."
    return "\n".join(
        [
            "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022",
            f"Connecting to {target} port 22.",
            f"Warning: Permanently added '{target}' (ED25519) to the list of known hosts.",
            authenticated,
            f"Linux {hostname} 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
            f"Last login: Tue Apr 21 23:14:02 2026 from {source_ip}",
        ]
    )


def redact_text(text: str) -> str:
    redacted = _PRIVATE_KEY.sub("[redacted private key]", text)
    redacted = _SECRET_VALUE.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
    redacted = _PGPASS.sub(r"\1[redacted]", redacted)
    return redacted.replace(_KNOWN_PASSWORD, "[redacted]")


def redact_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """公开回看时打码口令和私钥，结构保持不变。"""
    shown = _redact_node(snapshot)
    if isinstance(shown, dict):
        shown["redacted"] = True
    return shown


def present_world(snapshot: dict[str, Any], *, reveal: bool) -> dict[str, Any]:
    if reveal:
        shown = dict(snapshot)
        shown["redacted"] = False
        return shown
    return redact_snapshot(snapshot)


def _redact_node(node: Any) -> Any:
    if isinstance(node, dict):
        copied: dict[str, Any] = {}
        for key, value in node.items():
            if key == "preview" and isinstance(value, str):
                copied[key] = redact_text(value)
            else:
                copied[key] = _redact_node(value)
        return copied
    if isinstance(node, list):
        return [_redact_node(item) for item in node]
    return node


def _synthetic_file(name: str, hostname: str) -> str:
    if name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".gz"):
        return f"simulated archive {name} on {hostname}\nentries: nightly.sql, README\n"
    if name.endswith(".sh"):
        return f"#!/bin/bash\n# {name} on {hostname}\necho maintenance window\n"
    if name.endswith(".log"):
        return f"Apr 21 23:14:02 {hostname} {name}: rotation complete\n"
    if name.endswith(".db"):
        return "SQLite format 3\nsimulated cache, no rows exported\n"
    if name.endswith(".txt"):
        return f"{name}\noperator note on {hostname}. do not copy off box.\n"
    if name.endswith(".conf"):
        return f"# {name}\n# simulated on {hostname}\n"
    if "lock" in name:
        return "1234\n"
    return f"simulated {name} on {hostname}\n"


def _prepare(command: str) -> str:
    text = command.strip()
    text = re.sub(r"\s+2>\s*/dev/null", "", text)
    text = re.sub(r"\s+2>&1", "", text)
    text = re.sub(r"\s+</dev/null", "", text)
    return text.strip()


def _unwrap_shell_c(command: str) -> str | None:
    match = re.match(r"^(?:bash|sh)\s+-c\s+(.+)$", command, re.S)
    if not match:
        return None
    inner = match.group(1).strip()
    if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in {"'", '"'}:
        return inner[1:-1]
    return inner


def _split_sequence(text: str) -> list[tuple[str, str]]:
    parts: list[tuple[str, str]] = []
    buf: list[str] = []
    quote = ""
    index = 0
    pending = ""
    while index < len(text):
        char = text[index]
        if quote:
            buf.append(char)
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            buf.append(char)
            index += 1
            continue
        if text.startswith("&&", index):
            parts.append((pending, "".join(buf).strip()))
            buf = []
            pending = "&&"
            index += 2
            continue
        if char == ";":
            parts.append((pending, "".join(buf).strip()))
            buf = []
            pending = ";"
            index += 1
            continue
        buf.append(char)
        index += 1
    parts.append((pending, "".join(buf).strip()))
    return [(operator, piece) for operator, piece in parts if piece]


def _split_redirect(text: str) -> tuple[str, str | None, str | None]:
    quote = ""
    found: tuple[int, str] | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if text.startswith(">>", index):
            found = (index, ">>")
            index += 2
            continue
        if char == ">":
            found = (index, ">")
            index += 1
            continue
        index += 1
    if found is None:
        return text, None, None
    start, kind = found
    left = text[:start].strip()
    right = text[start + len(kind) :].strip()
    try:
        tokens = shlex.split(right)
    except ValueError:
        tokens = right.split()
    if not tokens:
        return text, None, None
    return left, kind, tokens[0]


def _split_unquoted(text: str, separator: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            buf.append(char)
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            buf.append(char)
            index += 1
            continue
        if char == separator:
            parts.append("".join(buf).strip())
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [part for part in parts if part]


def _positional(parts: list[str]) -> list[str]:
    return [part for part in parts[1:] if not part.startswith("-")]


def _positive_int(raw: str, default: int) -> int:
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def _failed(text: str) -> bool:
    lowered = text.lower()
    markers = (
        "no such file",
        "permission denied",
        "not a directory",
        "command not found",
        "missing operand",
        "is a directory",
    )
    return any(marker in lowered for marker in markers)


def _filter_lines(text: str, pattern: re.Pattern[str], *, invert: bool, number: bool, label: str) -> list[str]:
    matched: list[str] = []
    for index, line in enumerate(text.splitlines(), start=1):
        hit = pattern.search(line) is not None
        if hit == invert:
            continue
        prefix = f"{label}:" if label else ""
        if number:
            prefix = f"{prefix}{index}:"
        matched.append(f"{prefix}{line}" if prefix else line)
    return matched


def _split(path: str) -> tuple[str, str]:
    parent, _, name = path.rpartition("/")
    return (parent or "/"), name
