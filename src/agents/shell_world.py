"""会话内的虚拟主机。

常见命令只读写这一份世界。同一条 SSH 会话里 cd、touch、管道和重定向之后，下一条命令看得到。
模板来自资产类型，改动不会写回模板，也不会碰宿主机磁盘。
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
import ipaddress
import fnmatch
import re
import shlex
from typing import Any


# 无输出但退出码非 0 的命令（如 false）用哨兵把失败状态传给序列/管道逻辑。
_COMMAND_FAILED = "\x00command-failed"
_BUILTINS = {"echo", "printf", "cd", "pwd", "true", "false", "type", "command", "builtin", "alias", "declare", "enable", "export", "unset", "exit"}
_PROGRAMS = {"bash", "sh", "id", "whoami", "hostname", "uname", "ls", "cat", "head", "tail", "grep", "find", "wc", "env", "printenv", "which", "getent", "readlink", "ps", "ip", "ifconfig", "ss", "netstat", "date", "uptime", "nproc", "free", "who", "w", "hostnamectl", "systemd-detect-virt", "sort", "base64", "tr", "sed", "awk", "mkdir", "touch", "rm", "clear", "reset", "sudo", "ssh", "echo", "printf"}
_KERNEL = "5.15.0-92-generic"


def _program_name(name: str) -> str:
    if name.rpartition("/")[0] in {"/bin", "/usr/bin", "/sbin", "/usr/sbin"}:
        return name.rsplit("/", 1)[-1]
    return name


def _escapes(text: str) -> str:
    return re.sub(r"\\(0|n|t|r|\\)", lambda m: {"0":"\0", "n":"\n", "t":"\t", "r":"\r", "\\":"\\"}[m[1]], text)



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
        ip_address: str = "10.0.5.1",
    ) -> None:
        self.ip_address = ip_address
        self.asset_type = asset_type
        self.hostname = hostname
        self.username = username
        self.directories = {path: list(names) for path, names in directories.items()}
        self.files = dict(files)
        self.env_lines = list(env_lines)
        self.created: set[str] = set()
        self.planted: set[str] = set()
        self.cwd = "/var/tmp" if "/var/tmp" in self.directories else "/"
        # Every fixture has a visible directory entry, including hidden files.
        for path, content in list(self.files.items()):
            self._add_file(path, content)
        self._materialize_listed_files()
        self.last_status = 0
        self.variables = {"HOME": f"/home/{username}", "USER": username, "LOGNAME": username,
                          "SHELL": "/bin/bash", "SHLVL": "1", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                          "LANG": "C.UTF-8", "HOSTNAME": hostname, **dict(line.split("=", 1) for line in env_lines if "=" in line)}
        machine_id = hashlib.sha256(hostname.encode()).hexdigest()[:32]
        fixtures = {"/etc/shadow": "", "/etc/machine-id": machine_id + "\n", "/etc/resolv.conf": "nameserver 127.0.0.53\nsearch corp.local\n",
                    "/proc/self/status": f"Name:\tbash\nPid:\t4421\nUid:\t997\t997\t997\t997\nGid:\t997\t997\t997\t997\n",
                    "/proc/self/cmdline": "bash\0", "/proc/self/environ": "\0".join(f"{k}={v}" for k,v in self.variables.items()),
                    "/proc/uptime": "259200.00 510123.00\n", "/proc/version": f"Linux version {_KERNEL} (Ubuntu)\n",
                    "/proc/sys/kernel/hostname": hostname+"\n", f"/home/{username}/.bashrc": "# Interactive shell defaults\n",
                    "/etc/group": f"root:x:0:\n{username}:x:997:\n", "/etc/shells": "/bin/sh\n/bin/bash\n"}
        for path, content in list(fixtures.items()):
            if path.startswith("/proc/self/"):
                fixtures[path.replace("/proc/self/", "/proc/4421/")] = content
        for name in _PROGRAMS:
            for directory in ("/bin", "/usr/bin"):
                fixtures[f"{directory}/{name}"] = "\x7fELF"
        for path, content in fixtures.items():
            self._add_file(path, content)


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
        loop = re.fullmatch(r"for\s+([A-Za-z_][A-Za-z_0-9]*)\s+in\s+(.*?)[;\n]\s*do\s+(.*?)[;\n]\s*done\s*;?", text, re.S)
        if loop:
            # Read-only inventory loops used by SSH agents, evaluated in this world.
            outputs = []
            for value in shlex.split(self._expand(loop[2])):
                self.variables[loop[1]] = value
                output = self.execute(loop[3])
                if output is None:
                    output = f"bash: {shlex.split(loop[3])[0]}: command not found"
                if output: outputs.append(output)
            return "\n".join(outputs)
        pieces = _split_sequence(text)
        if len(pieces) > 1:
            return self._run_sequence(pieces)
        result = self._run_redirect(pieces[0][1] if pieces else text)
        if result == _COMMAND_FAILED:
            return ""
        return result

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
        if text == "~" or text.startswith("~/"):
            text = "/home/" + self.username + text[1:]
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
            if directory != normalized and not directory.startswith(normalized.rstrip("/") + "/"):
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
                continue
            if operator == "||" and not last_failed:
                continue
            result = self._run_redirect(piece)
            if result is None:
                result = f"bash: {shlex.split(piece)[0]}: command not found"
                self.last_status = 127
            last_failed = self.last_status != 0
            if result and result != _COMMAND_FAILED:
                outputs.append(result)
        return "\n".join(outputs)

    def _run_redirect(self, text: str) -> str | None:
        # Redirections apply to this command only, never to quoted script contents.
        text, silent = _strip_fd_redirects(text)
        command, mode, target = _split_redirect(text)
        result = self._pipeline(command)
        if result is not None:
            self.last_status = 1 if result == _COMMAND_FAILED or _failed(result) else 0
            if silent and self.last_status:
                result = _COMMAND_FAILED
        if result is None or mode is None or target is None:
            return result
        if result == _COMMAND_FAILED:
            return _COMMAND_FAILED
        error = self._write_redirect(target, result, append=mode == ">>")
        if error:
            return error
        return ""

    def _pipeline(self, text: str) -> str | None:
        stages = _split_unquoted(text, "|")
        if not stages:
            return ""
        data: str | None = None
        failed = False
        for index, stage in enumerate(stages):
            result = self._simple(stage, stdin=data if index else None)
            if result is None:
                if len(stages) == 1:
                    return None
                result = f"bash: {shlex.split(stage)[0]}: command not found"
            failed = result == _COMMAND_FAILED
            data = "" if failed else result
        if failed:
            return _COMMAND_FAILED
        return data or ""

    def _simple(self, text: str, stdin: str | None) -> str | None:
        if text.startswith("(") and text.endswith(")"):
            return self.execute(text[1:-1])
        try:
            parts = shlex.split(self._expand(text))
        except ValueError:
            return "bash: syntax error: unmatched quote"
        if not parts:
            return stdin or ""
        name = _program_name(parts[0])
        parts[0] = name
        if name in {"bash", "sh"}:
            option = next((i for i,x in enumerate(parts[1:], 1) if x.startswith("-") and "c" in x), None)
            if option is not None:
                return self.execute(parts[option + 1]) if option + 1 < len(parts) else "bash: -c: option requires an argument"
            args = _positional(parts)
            if args:
                path = self.resolve(args[0])
                if path not in self.files:
                    return f"bash: {args[0]}: No such file or directory"
                script = "\n".join(line for line in self.files[path].splitlines() if not line.lstrip().startswith("#"))
                return self.execute(script)
            return self.execute(stdin) if stdin else ""
        if name in {"command", "builtin"} and len(parts)>1 and parts[1] not in {"-v", "-V"}:
            return self._simple(shlex.join(parts[1:]), stdin)
        extra = self._probe_command(name, parts, stdin)
        if extra is not None:
            return extra
        if name in {"clear", "reset"}:
            return "\033[H\033[2J\033[3J"
        if name == "sudo" and (len(parts) == 1 or parts[1] in {"-h", "--help"}):
            return "usage: sudo -h | -V | -l\nusage: sudo [-u user] command [arg ...]"
        if name == "sudo" and parts[1] in {"-V", "--version"}:
            return "Sudo version 1.9.9"
        if name == "true":
            return ""
        if name == "false":
            return _COMMAND_FAILED
        if name == "pwd":
            return self.cwd
        if name == "whoami":
            return self.username
        if name == "hostname":
            return self.hostname
        if name == "id":
            flags = "".join(p.lstrip("-") for p in parts[1:] if p.startswith("-"))
            if any(c in flags for c in "ugG"):
                return self.username if "n" in flags else "997"
            return f"uid=997({self.username}) gid=997({self.username}) groups=997({self.username})"
        if name == "uname":
            flags = "".join(p.lstrip("-") for p in parts[1:] if p.startswith("-")) or "s"
            values = {"s":"Linux", "n":self.hostname, "r":_KERNEL, "v":"#102-Ubuntu SMP PREEMPT_DYNAMIC", "m":"x86_64", "p":"x86_64", "i":"x86_64", "o":"GNU/Linux"}
            return " ".join(values[k] for k in ("snrvmo" if "a" in flags else "snrvmpio") if "a" in flags or k in flags)
        if name == "ip" and len(parts) > 1 and parts[1] in {"route", "r"}:
            subnet = self.ip_address.rsplit(".", 1)[0]
            return f"default via {subnet}.254 dev eth0\n{subnet}.0/24 dev eth0 proto kernel scope link src {self.ip_address}"
        if name == "ip" and "neigh" in parts:
            return f"{self.ip_address.rsplit('.',1)[0]}.254 dev eth0 lladdr 02:42:ac:11:00:01 REACHABLE"
        if name == "ip" and "-br" in parts:
            return f"lo UNKNOWN 127.0.0.1/8\neth0 UP {self.ip_address}/24"
        if name in {"ip", "ifconfig"}:
            return f"1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet {self.ip_address}/24 scope global eth0"
        if name in {"ss", "netstat"}:
            port, service = (5432, "postgres") if self.asset_type == "database_server" else (80, "nginx")
            return f'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=901,fd=3))\nLISTEN 0 128 {self.ip_address}:{port} 0.0.0.0:* users:(("{service}",pid=2112,fd=5))'
        if name == "ps":
            service = "postgres" if self.asset_type == "database_server" else "nginx"
            return f"USER PID TTY STAT COMMAND\nroot 1 ? Ss /sbin/init\nroot 901 ? Ss /usr/sbin/sshd -D\n{self.username} 4421 pts/0 Ss bash\n{self.username} 2112 ? S {service}"
        if name in {"env", "printenv"}:
            variables = {**self.variables, "PWD": self.cwd}
            if name == "printenv" and len(parts)>1:
                return "\n".join(variables[p] for p in parts[1:] if p in variables)
            return "\n".join(f"{k}={v}" for k,v in variables.items())
        if name == "echo":
            return self._echo(parts)
        if name == "cd":
            args = _positional(parts)
            return self._cd(args[0] if args else f"/home/{self.username}")
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
            return self._rm(parts)
        if name == "head":
            return self._head_tail(parts, stdin, tail=False)
        if name == "tail":
            return self._head_tail(parts, stdin, tail=True)
        if name == "grep":
            return self._grep(parts, stdin)
        if name == "wc":
            return self._wc(parts, stdin)
        return None

    def _expand(self, text: str) -> str:
        """Expand virtual shell values only; never evaluate on the host OS."""
        out = []
        quote = ""
        i = 0
        values = {**self.variables, "PWD": self.cwd, "UID": "997", "EUID": "997", "?": str(self.last_status), "$": "4421", "0": "bash"}
        while i < len(text):
            c = text[i]
            if c == "\\" and quote != "'" and i+1 < len(text):
                out.append(text[i:i+2]); i += 2; continue
            if c in {"'", '"'}:
                if not quote: quote = c
                elif quote == c: quote = ""
                out.append(c); i += 1; continue
            if c != "$" or quote == "'":
                out.append(c); i += 1; continue
            if text.startswith("$(", i):
                end = i+2; depth = 1; inner_quote = ""
                while end < len(text) and depth:
                    ch = text[end]
                    if ch == "\\" and inner_quote != "'": end += 2; continue
                    if inner_quote:
                        if ch == inner_quote: inner_quote = ""
                    elif ch in {"'", '"'}: inner_quote = ch
                    elif ch == "(": depth += 1
                    elif ch == ")": depth -= 1
                    end += 1
                if depth: raise ValueError("unclosed substitution")
                value = self.execute(text[i+2:end-1]) or ""
                i = end
            else:
                match = re.match(r"\$(?:\{([A-Za-z_][A-Za-z_0-9]*)\}|([A-Za-z_][A-Za-z_0-9]*|[?$0]))", text[i:])
                if not match: out.append(c); i += 1; continue
                value = values.get(match[1] or match[2], "")
                i += len(match[0])
            value = value.rstrip("\n")
            out.append(value.replace("\\", "\\\\").replace('"', '\\"') if quote == '"' else shlex.quote(value))
        return "".join(out)

    def _probe_command(self, name: str, parts: list[str], stdin: str | None) -> str | None:
        args = parts[1:]
        if name in {"type", "which"} or name == "command" and args and args[0] in {"-v", "-V"}:
            items = [a for a in args if not a.startswith("-")]
            results = []
            for item in items:
                program = _program_name(item)
                if program in _BUILTINS:
                    results.append(f"{item} is a shell builtin" if name == "type" else item)
                elif program in _PROGRAMS:
                    path = f"/bin/{program}" if program in {"bash", "sh"} else f"/usr/bin/{program}"
                    results.append(f"{item} is {path}" if name == "type" else path)
                else:
                    results.append(f"bash: type: {item}: not found" if name == "type" else "")
            return "\n".join(x for x in results if x) or _COMMAND_FAILED
        if name in {"alias", "declare"}: return ""
        if name == "enable": return "\n".join(f"enable {k}" for k in sorted(_BUILTINS))
        if name == "export":
            for arg in args:
                if "=" in arg:
                    key,value = arg.split("=",1); self.variables[key] = value
            return ""
        if name == "unset":
            for arg in args: self.variables.pop(arg,None)
            return ""
        if name == "printf":
            if args and args[0] == "--": args = args[1:]
            if not args: return "printf: usage: printf format [arguments]"
            fmt = _escapes(args[0]); rest = iter(args[1:])
            return re.sub(r"%[%sdb]", lambda m: "%" if m[0]=="%%" else (_escapes(next(rest,"")) if m[0]=="%b" else next(rest,"0" if m[0]=="%d" else "")), fmt)
        if name == "getent":
            paths = {"passwd":"/etc/passwd", "group":"/etc/group", "hosts":"/etc/hosts"}
            if not args or args[0] not in paths: return _COMMAND_FAILED
            data = self.files.get(paths[args[0]], "")
            if len(args)>1:
                data = "\n".join(line for line in data.splitlines() if args[1] in (line.split() if args[0]=="hosts" else line.split(":")))
            return data.rstrip("\n") or _COMMAND_FAILED
        if name == "readlink":
            path = args[-1] if args else ""
            if path in {"/proc/self/exe", "/proc/4421/exe"}: return "/usr/bin/bash"
            if path in {"/proc/self/cwd", "/proc/4421/cwd"}: return self.cwd
            return self.resolve(path) if "-f" in args else _COMMAND_FAILED
        if name == "hostnamectl": return f"Static hostname: {self.hostname}\nOperating System: Ubuntu 22.04.5 LTS\nKernel: Linux {_KERNEL}\nArchitecture: x86-64"
        if name == "date":
            now = datetime.now(timezone.utc)
            return now.strftime(args[0][1:]) if args and args[0].startswith("+") else now.strftime("%a %b %d %H:%M:%S UTC %Y")
        if name == "uptime": return "up 3 days, 1 user, load average: 0.12, 0.09, 0.05"
        if name == "nproc": return "2"
        if name == "free": return "               total        used        free\nMem:           3.8Gi       512Mi       3.3Gi\nSwap:             0B          0B          0B"
        if name == "systemd-detect-virt": return "kvm"
        if name in {"who", "w"}: return f"{self.username} pts/0 2026-09-24 03:00 (127.0.0.1)"
        if name == "sort": return "\n".join(sorted((stdin or "").splitlines()))
        if name == "base64":
            paths = [a for a in args if not a.startswith("-")]
            data = self._cat(self.resolve(paths[-1])) if paths else stdin or ""
            if any(x in args for x in ("-d", "--decode")):
                try: return base64.b64decode(data).decode("utf-8", errors="replace")
                except ValueError: return "base64: invalid input"
            return base64.b64encode((data + ("\n" if paths else "")).encode()).decode()
        if name == "tr":
            if len(args)<2:return "tr: missing operand"
            source,target = _escapes(args[-2]),_escapes(args[-1])
            return (stdin or "").translate(str.maketrans({c: target[min(i,len(target)-1)] if target else None for i,c in enumerate(source)}))
        if name == "awk" and args and args[0] == "1": return stdin or ""
        if name == "sed" and args and args[0] == "-n":
            match = re.fullmatch(r"(\d+)(?:,(\d+))?p", args[1] if len(args)>1 else "")
            if match:
                data = self._cat(self.resolve(args[2])) if len(args)>2 else stdin or ""
                return "\n".join(data.splitlines()[int(match[1])-1:int(match[2] or match[1])])
        return None

    def _rm(self, parts: list[str]) -> str:
        """删除会话内的虚拟文件，并同步目录列表和快照标记。"""
        args = _positional(parts)
        options = [part for part in parts[1:] if part.startswith("-")]
        recursive = any("r" in option or "R" in option for option in options)
        force = any("f" in option for option in options)
        if not args:
            return "" if force else "rm: missing operand"
        errors = []
        for raw in args:
            pattern = self.resolve(raw)
            paths = sorted(path for path in set(self.files) | set(self.directories)
                           if path.count("/") == pattern.count("/") and fnmatch.fnmatchcase(path, pattern)) if any(c in raw for c in "*?[") else [pattern]
            for path in paths or [pattern]:
                if path == "/":
                    errors.append("rm: it is dangerous to operate recursively on '/'")
                    continue
                if path not in self.files and path not in self.directories:
                    if not force:
                        errors.append(f"rm: cannot remove '{raw}': No such file or directory")
                    continue
                if path in self.directories and not recursive:
                    errors.append(f"rm: cannot remove '{raw}': Is a directory")
                    continue
                removed = {p for p in set(self.files) | set(self.directories)
                           if p == path or p.startswith(path + "/")}
                for item in removed:
                    self.files.pop(item, None)
                    self.directories.pop(item, None)
                self.created.difference_update(removed)
                self.planted.difference_update(removed)
                parent, name = _split(path)
                if name in self.directories.get(parent, []):
                    self.directories[parent].remove(name)
        return "\n".join(errors)

    def _echo(self, parts: list[str]) -> str:
        args = parts[1:]
        interpret = bool(args and "e" in args[0] and args[0].startswith("-"))
        if args and args[0] in {"-n", "-e", "-ne", "-en"}:
            args = args[1:]
        text = " ".join(args)
        return _escapes(text) if interpret else text

    def _ls_command(self, parts: list[str]) -> str:
        flags = "".join(part.lstrip("-") for part in parts[1:] if part.startswith("-"))
        paths = _positional(parts) or [self.cwd]
        outputs = []
        for raw in paths:
            path = self.resolve(raw)
            if "d" in flags and (path in self.files or path in self.directories):
                result = self._ls_line(raw, path) if "l" in flags else raw
            else:
                result = self._ls(raw, long_format="l" in flags,
                                  show_all="a" in flags or "A" in flags, dot_entries="a" in flags)
            if (len(paths) > 1 or "R" in flags) and path in self.directories and "d" not in flags:
                result = f"{raw}:\n{result}"
            if "R" in flags and "d" not in flags:
                for child in sorted(self.directories):
                    if child != path and child.startswith(path.rstrip("/")+"/"):
                        if "a" not in flags and "A" not in flags and any(p.startswith(".") for p in child.split("/")): continue
                        result += f"\n\n{child}:\n" + self._ls(child, long_format="l" in flags, show_all="a" in flags or "A" in flags, dot_entries="a" in flags)
            outputs.append(result)
        return "\n\n".join(outputs)

    def _cat_command(self, parts: list[str], stdin: str | None) -> str:
        args = _positional(parts)
        if not args:
            return stdin or ""
        chunks: list[str] = []
        for raw in args:
            path = self.resolve(raw)
            if path in self.files or path in self.directories or path == "/etc/shadow":
                chunks.append(self._cat(path))
                continue
            chunks.append(f"cat: {raw}: No such file or directory")
        return "\n".join(chunks)

    def _find_command(self, parts: list[str]) -> str:
        root = self.cwd
        pattern = "*"
        kind = ""
        max_depth = None
        i = 1
        while i < len(parts):
            token = parts[i]
            if token in {"-name", "-iname", "-type", "-maxdepth", "-mindepth"} and i+1<len(parts):
                value = parts[i+1]
                if token in {"-name", "-iname"}: pattern = value
                elif token == "-type": kind = value
                elif token == "-maxdepth": max_depth = _positive_int(value, 99)
                i += 2
            elif token.startswith("-"):
                i += 1
            else:
                root = token
                i += 1
        path = self.resolve(root)
        candidates = sorted(set(self.files) | set(self.directories))
        if path not in candidates: return f"find: '{root}': No such file or directory"
        result = []
        for item in candidates:
            if item != path and not item.startswith(path.rstrip("/")+"/"): continue
            depth = len(item[len(path.rstrip("/")):].strip("/").split("/")) if item!=path else 0
            if max_depth is not None and depth>max_depth: continue
            if kind=="f" and item not in self.files or kind=="d" and item not in self.directories: continue
            if fnmatch.fnmatch(item.rsplit("/",1)[-1],pattern): result.append(item)
        return "\n".join(result)

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
            if path == "/etc/shadow":
                return f"{command}: cannot open '/etc/shadow' for reading: Permission denied"
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

    def _ls(self, raw: str, *, long_format: bool = False, show_all: bool = False, dot_entries: bool = False) -> str:
        path = self.resolve(raw)
        if path in self.directories:
            names = sorted(name for name in self.directories[path] if show_all or not name.startswith("."))
            if dot_entries:
                names = [".", "..", *names]
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
        owner = "root" if path.startswith(("/etc/", "/bin/", "/usr/bin/", "/proc/")) else self.username
        if path == "/etc/shadow": mode = "-rw-------"
        elif path.startswith(("/bin/", "/usr/bin/")) and path in self.files: mode = "-rwxr-xr-x"
        return f"{mode} 1 {owner:<12} {owner:<12} {size:6} Sep 22 03:15 {name}"

    def _is_listed(self, path: str) -> bool:
        parent, name = _split(path)
        return bool(name) and name in self.directories.get(parent, [])

    def _cat(self, path: str) -> str:
        if path == "/etc/shadow":
            return "cat: /etc/shadow: Permission denied"
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
        current = ""
        for component in parent.strip("/").split("/"):
            if not component: continue
            ancestor = current or "/"
            current += "/" + component
            self.directories.setdefault(current, [])
            siblings = self.directories.setdefault(ancestor, [])
            if component not in siblings: siblings.append(component)
        if name and name not in self.directories[parent]:
            self.directories[parent].append(name)
        self.files[path] = content
        if planted:
            self.planted.add(path)
        if created:
            self.created.add(path)


def ssh_hop_banner(*, target: str, hostname: str, source_ip: str) -> str:
    """内层跳转的非交互登录记录。不向攻击者再要一次 yes 或口令。"""
    return "\n".join(
        [
            "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022",
            f"Connecting to {target} port 22.",
            f"Warning: Permanently added '{target}' (ED25519) to the list of known hosts.",
            f"Authenticated to {target}.",
            f"Linux {hostname} 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
            f"Last login: Tue Sep 22 03:15:02 2026 from {source_ip}",
        ]
    )


def _synthetic_file(name: str, hostname: str) -> str:
    """Unimportant leftover listing entries are empty, not self-identifying placeholders."""
    if name.endswith(".tar.gz"):
        return "\x1f\x8b\x08\x00finance-export.tar\x00"
    if name.endswith(".db"):
        return "SQLite format 3\x00"
    if "lock" in name:
        return "1842\n"
    return ""


SSH_HOSTS = {"web-pivot-01": "10.0.5.1", "db-replica-01": "10.0.5.2",
             "finance-replica": "10.0.5.2", "oss-sync-bridge": "10.0.8.7", "oss-archive": "10.0.8.7"}


def parse_ssh_command(command: str) -> tuple[str, str] | None:
    """Return destination IP and optional remote command after SSH options."""
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or _program_name(parts[0]) != "ssh":
        return None
    i = 1
    value_options = set("bcDEeFIiJLlmOopQRSWw")
    while i < len(parts):
        token = parts[i]
        if token == "--":
            i += 1
            break
        if not token.startswith("-"):
            break
        i += 2 if len(token) == 2 and token[1] in value_options else 1
    if i >= len(parts):
        return None
    host = parts[i].rsplit("@", 1)[-1]
    target = SSH_HOSTS.get(host)
    if target is None:
        try:
            target = str(ipaddress.IPv4Address(host))
        except ValueError:
            return None
    tail = parts[i + 1:]
    remote = tail[0] if len(tail) == 1 else shlex.join(tail)
    return target, remote


def ssh_destination(command: str) -> str | None:
    parsed = parse_ssh_command(command)
    return parsed[0] if parsed else None


def _prepare(command: str) -> str:
    return command.strip()


def _operators(text: str):
    """Yield only unquoted, top-level shell operators (including newlines)."""
    quote = ""
    depth = 0
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = ""
        elif c in {"'", '"'}:
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0:
            op = next((v for v in ("&&", "||", ">>", ";", "\n", "|", ">") if text.startswith(v, i)), None)
            if op:
                yield i, op
                i += len(op)
                continue
        i += 1


def _split_sequence(text: str) -> list[tuple[str, str]]:
    result = []
    start = 0
    pending = ""
    for i, op in _operators(text):
        if op in {"&&", "||", ";", "\n"}:
            result.append((pending, text[start:i].strip()))
            pending, start = op, i+len(op)
    result.append((pending, text[start:].strip()))
    return [(op, part) for op,part in result if part]


def _strip_fd_redirects(text: str) -> tuple[str, bool]:
    silent = False
    spans = []
    for i,op in _operators(text):
        if op != ">" or i == 0 or text[i-1] != "2":
            continue
        match = re.match(r"2>\s*(/dev/null|&1)(?=\s|$)", text[i-1:])
        if match:
            silent |= match[1] == "/dev/null"
            spans.append((i-1,i-1+len(match[0])))
    for a,z in reversed(spans):
        text = text[:a]+text[z:]
    return text.strip(), silent


def _split_redirect(text: str) -> tuple[str, str | None, str | None]:
    found = [(i,op) for i,op in _operators(text) if op in {">", ">>"}]
    if not found:
        return text, None, None
    i,op = found[-1]
    targets = shlex.split(text[i+len(op):])
    return (text[:i].strip(), op, targets[0]) if targets else (text,None,None)


def _split_unquoted(text: str, separator: str) -> list[str]:
    result = []
    start = 0
    for i,op in _operators(text):
        if op == separator:
            result.append(text[start:i].strip())
            start = i+len(op)
    result.append(text[start:].strip())
    return [part for part in result if part]


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
