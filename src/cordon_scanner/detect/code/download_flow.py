"""Whether what a script downloads is what it runs.

`MALWARE.DROPPER.001` pairs a network fetch with an execution within two hundred lines. In an
install hook that pair is the attack: the hook runs unasked on a consumer's machine. A skill's
helper script is run by the agent on request, and fetching beside running is what such a
script is for -- `curl "$api" | jq` to read a timetable, `python3 -c` to url-encode an argument.
Measured on review 98: the dropper rules were the only blocking finding on 40 of 4,000 benign
MalSkillBench skills and 21 of 9,999 public skills.

A dropper runs what it downloaded. This follows the downloaded bytes: into a pipe, a variable,
a file (and that file's copies, moves and unpacked directory), and asks whether any of them is
executed -- as a program, as an interpreter's script, by `eval`, `exec`, or a spawned command.

```
  download ──► stdout | interpreter ─────────────────────────────► RUNS
           ──► $(…) variable ──► eval / sh -c / | sh ────────────► RUNS
           ──► -o FILE ──► cp/mv ──► tar -x -C DIR ──► ./DIR/x ──► RUNS
           ──► python: urlopen().read() ──► exec / write(P) ──► subprocess([P]) ──► RUNS
```

Shell and Python are read; for any other language, and for Python that does not parse,
`runs_download` returns None and the caller keeps the co-occurrence verdict.
"""

from __future__ import annotations

import ast
import re
import shlex
from typing import ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class ShellDownloads:
    """The downloaded-bytes flow in a shell script, read statement by statement."""

    _FETCHERS: ClassVar[frozenset[str]] = frozenset(
        {"curl", "wget", "fetch", "iwr", "invoke-webrequest", "aria2c", "http", "https"}
    )
    _INTERPRETERS: ClassVar[frozenset[str]] = frozenset(
        {
            "sh",
            "bash",
            "zsh",
            "ksh",
            "dash",
            "python",
            "python2",
            "python3",
            "node",
            "perl",
            "ruby",
            "php",
            "source",
            ".",
            "pwsh",
            "powershell",
            "osascript",
        }
    )
    _PREFIXES: ClassVar[frozenset[str]] = frozenset(
        {
            "sudo",
            "nohup",
            "exec",
            "env",
            "time",
            "nice",
            "setsid",
            "command",
            "builtin",
            "then",
            "do",
            "else",
            "!",
            "{",
            "(",
        }
    )
    _UNPACKERS: ClassVar[frozenset[str]] = frozenset({"tar", "unzip", "7z", "bsdtar"})
    _CODE_FLAGS: ClassVar[frozenset[str]] = frozenset({"-c", "-e", "-E", "-m", "-n", "-p", "-l"})
    _CAPTURE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:export\s{1,8}|local\s{1,8}|readonly\s{1,8})?([A-Za-z_]\w{0,60})=(.{0,4000})$"
    )
    _VAR: ClassVar[re.Pattern[str]] = re.compile(r"\$\{?([A-Za-z_]\w{0,60})\}?")

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.tainted_vars: set[str] = set()
        self.tainted_paths: set[str] = set()
        self.tainted_dirs: set[str] = set()

    @classmethod
    def runs(cls, text: str) -> list[int]:
        """Lines on which a script executes what it downloaded."""
        flow = cls()
        hits: list[int] = []
        for number, statement in cls._statements(text):
            if flow._statement(statement):
                hits.append(number)
        return hits

    _HEREDOC: ClassVar[re.Pattern[str]] = re.compile(r"<<-?\s{0,4}['\"]?([A-Za-z_]\w{0,40})['\"]?")
    _TEST: ClassVar[re.Pattern[str]] = re.compile(
        r"\[\[[^\n]{0,400}?\]\]|(?<![\w$])\[\s[^\n\]]{0,400}\s\]"
    )

    @classmethod
    def _statements(cls, text: str) -> list[tuple[int, str]]:
        """(line, statement): continuations joined, heredoc bodies and `[[ ]]` tests set aside,
        and split on `;`, `&&`, `||` and newlines outside quotes and `$( )`."""
        out: list[tuple[int, str]] = []
        pending, start, heredoc = "", 0, None
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.rstrip()
            if heredoc is not None:
                if line.strip() == heredoc:
                    heredoc = None
                continue
            if not pending:
                start = number
            if line.endswith("\\"):
                pending += line[:-1] + " "
                continue
            joined = (pending + line).strip()
            pending = ""
            marker = cls._HEREDOC.search(joined)
            if marker:
                heredoc = marker.group(1)
            if not joined or joined.startswith("#"):
                continue
            joined = cls._TEST.sub(" true ", joined)
            out.extend((start, part) for part in cls._split(joined))
        return out

    @staticmethod
    def _split(line: str) -> list[str]:
        parts, current, depth, quote, i = [], [], 0, "", 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\" and quote == '"' and i + 1 < len(line):
                    current.append(line[i : i + 2])
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "#" and (not current or "".join(current)[-1:].isspace()) and depth == 0:
                break
            elif line.startswith("$(", i):
                depth += 1
            elif ch == ")" and depth:
                depth -= 1
            elif depth == 0 and (ch == ";" or line.startswith(("&&", "||"), i)):
                parts.append("".join(current).strip())
                current = []
                i += 1 if ch == ";" else 2
                continue
            current.append(ch)
            i += 1
        parts.append("".join(current).strip())
        return [p for p in parts if p]

    def _expand(self, word: str) -> str:
        word = word.strip("\"'")
        return self._VAR.sub(lambda m: self.values.get(m.group(1), m.group(0)), word)

    def _is_tainted_word(self, word: str, whole: bool = False) -> bool:
        """Whether a word carries downloaded content; `whole`: the word is nothing else."""
        bare = word.strip("\"'")
        for v in self.tainted_vars:
            if whole and bare in (f"${v}", f"${{{v}}}"):
                return True
            if not whole and (f"${v}" in word or f"${{{v}}}" in word):
                return True
        return self._is_tainted_path(word)

    def _is_tainted_path(self, word: str) -> bool:
        path = self._expand(word)
        if not path or "$" in path.replace("$(", ""):
            return False
        trimmed = path[2:] if path.startswith("./") else path
        if "." in self.tainted_dirs and not trimmed.startswith(("/", "~", "-")):
            return True  # inside a downloaded tree, every relative path is downloaded content
        return (
            path in self.tainted_paths
            or trimmed in self.tainted_paths
            or any(trimmed.startswith(d.rstrip("/") + "/") for d in self.tainted_dirs if d)
        )

    @staticmethod
    def _words(segment: str) -> list[str]:
        try:
            return shlex.split(segment, comments=False, posix=True)
        except ValueError:
            return segment.split()

    def _command(self, words: list[str]) -> list[str]:
        """The words after leading assignments and wrappers (`sudo`, `nohup`, `env X=1`)."""
        i = 0
        while i < len(words) and (
            words[i] in self._PREFIXES or re.fullmatch(r"[A-Za-z_]\w{0,60}=.{0,400}", words[i])
        ):
            i += 1
        return words[i:]

    def _fetch_output(self, words: list[str]) -> str | None:
        """The file a download writes to, when it names one."""
        for i, word in enumerate(words):
            if word in ("-o", "--output", "-O", "--output-document", "-OutFile", "-outfile"):
                if word == "-O" and words[0].lower() == "curl":
                    url = next((w for w in words if "://" in w), "")
                    return url.rstrip("/").rsplit("/", 1)[-1].split("?")[0] or None
                if i + 1 < len(words):
                    return self._expand(words[i + 1])
            for flag in ("--output=", "--output-document=", "-O"):
                if word.startswith(flag) and len(word) > len(flag) and flag != "-O":
                    return self._expand(word[len(flag) :])
        return None

    def _executes(self, words: list[str], piped_in: bool) -> bool:
        """Whether this command runs tainted content."""
        cmd = self._command(words)
        if not cmd:
            return False
        head = cmd[0].lower().rsplit("/", 1)[-1]
        if self._is_tainted_word(cmd[0], whole=True):
            return True
        if head == "eval":
            return len(cmd) > 1 and self._is_tainted_word(cmd[1], whole=True)
        if head == "chmod" and any(
            re.fullmatch(r"(?:[ugoa]{0,3}\+[rw]{0,2}x\w{0,2}|[0-7]?[1357][0-7]{2})", a)
            for a in cmd[1:]
        ):
            # Making a downloaded file executable has one purpose.
            return any(
                self._is_tainted_word(a)
                for a in cmd[1:]
                if not a.startswith(("+", "-")) and not a.isdigit()
            )
        if head in self._INTERPRETERS:
            args = cmd[1:]
            if any(a in self._CODE_FLAGS for a in args):
                after = args[args.index(next(a for a in args if a in self._CODE_FLAGS)) + 1 :]
                return bool(after) and self._is_tainted_word(after[0])
            script = next((a for a in args if not a.startswith("-")), None)
            if script is None:
                return piped_in
            return self._is_tainted_word(script, whole=True) or self._is_tainted_path(script)
        if head in ("xargs",) and piped_in:
            return False
        return False

    def _statement(self, statement: str) -> bool:
        captured = self._CAPTURE.match(statement)
        if captured and not statement.startswith(("if ", "while ")):
            name, value = captured.group(1), captured.group(2)
            inner = value.strip()
            if inner.startswith(("$(", "`", '"$(', '"`')):
                body = inner.strip('"').lstrip("$(`").rstrip(")`")
                first = self._command(self._words(body.split("|", 1)[0]))
                if first and first[0].lower() in self._FETCHERS and "-o" not in first:
                    self.tainted_vars.add(name)
                    return False
            if self._is_tainted_word(inner):
                self.tainted_vars.add(name)
            self.values[name] = self._expand(inner)
            return False
        segments = [s for s in re.split(r"(?<!\|)\|(?!\|)", statement) if s.strip()]
        stream_tainted = False
        for index, segment in enumerate(segments):
            redirect = re.search(r"(?<![<>&\d])>{1,2}\s{0,4}(\S{1,400})", segment)
            words = self._words(re.sub(r"(?<![<>&\d])>{1,2}\s{0,4}\S{1,400}", " ", segment))
            cmd = self._command(words)
            head = cmd[0].lower().rsplit("/", 1)[-1] if cmd else ""
            if head in self._FETCHERS:
                output = self._fetch_output(cmd)
                if output and output != "-":
                    self.tainted_paths.add(output)
                    stream_tainted = False
                else:
                    stream_tainted = True
            elif head in ("echo", "printf", "cat") and any(
                self._is_tainted_word(w) for w in cmd[1:]
            ):
                stream_tainted = True
            elif index and stream_tainted:
                if self._executes(words, piped_in=True):
                    return True
                if head in self._UNPACKERS:
                    target = self._unpack_target(cmd)
                    if target is not None:
                        self.tainted_dirs.add(target)
                stream_tainted = head in ("base64", "gunzip", "gzip", "xxd", "openssl", "tr", "rev")
            else:
                if self._executes(words, piped_in=False):
                    return True
                if head in ("cp", "mv", "install", "ln") and len(cmd) >= 3:
                    sources = [w for w in cmd[1:-1] if not w.startswith("-")]
                    if any(self._is_tainted_word(s) for s in sources):
                        self.tainted_paths.add(self._expand(cmd[-1]))
                if head in self._UNPACKERS and any(self._is_tainted_word(w) for w in cmd[1:]):
                    target = self._unpack_target(cmd)
                    self.tainted_dirs.add(target if target is not None else ".")
                if head == "git" and len(cmd) > 2 and cmd[1] == "clone":
                    # A checkout is a download: what it holds is whatever the remote serves.
                    places = [w for w in cmd[2:] if not w.startswith("-")]
                    if places:
                        repo = places[0].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                        self.tainted_dirs.add(self._expand(places[1]) if len(places) > 1 else repo)
                if (
                    head == "cd"
                    and len(cmd) > 1
                    and (
                        self._expand(cmd[1]).rstrip("/") in self.tainted_dirs
                        or self._is_tainted_path(cmd[1])
                    )
                ):
                    self.tainted_dirs.add(".")
                stream_tainted = False
            if redirect and stream_tainted:
                self.tainted_paths.add(self._expand(redirect.group(1)))
                stream_tainted = False
        return False

    def _unpack_target(self, cmd: list[str]) -> str | None:
        for flag in ("-C", "-d", "--directory"):
            if flag in cmd and cmd.index(flag) + 1 < len(cmd):
                return self._expand(cmd[cmd.index(flag) + 1])
        return "."


class PythonDownloads:
    """The downloaded-bytes flow in a Python file, read from its syntax tree."""

    _FETCH_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "urlopen",
            "get",
            "post",
            "request",
            "stream",
            "urlretrieve",
            "download_file",
            "retrieve",
            "read",
            "content",
            "text",
            "json",
            "iter_content",
            "raw",
            "getresponse",
        }
    )
    _FETCH_MODULES: ClassVar[frozenset[str]] = frozenset(
        {
            "requests",
            "httpx",
            "urllib",
            "request",
            "urllib3",
            "session",
            "client",
            "aiohttp",
            "http",
            "conn",
            "connection",
            "s",
            "sess",
            "pool",
        }
    )
    _RUNNERS: ClassVar[frozenset[str]] = frozenset(
        {
            "system",
            "popen",
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "startfile",
            "execv",
            "execve",
            "execvp",
            "execl",
            "execlp",
            "spawnv",
            "spawnl",
            "run_path",
            "create_subprocess_exec",
            "create_subprocess_shell",
            "getoutput",
            "getstatusoutput",
        }
    )

    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.tainted: set[str] = set()
        self.paths: set[str] = set()
        self.constants: dict[str, str] = {}
        self.inside_download = False
        """The working directory is a downloaded tree (`os.chdir` into a checkout)."""

    @classmethod
    def runs(cls, text: str) -> list[int] | None:
        try:
            tree = PythonSyntax.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return None
        flow = cls(tree)
        # Twice: a helper defined below its caller taints on the second pass.
        for _ in range(2):
            hits = flow._walk()
        return hits

    @staticmethod
    def _name(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:  # noqa: BLE001
            return ""

    def _callee(self, call: ast.Call) -> tuple[str, str]:
        func = call.func
        if isinstance(func, ast.Attribute):
            return self._name(func.value).rsplit(".", 1)[-1], func.attr
        if isinstance(func, ast.Name):
            return "", func.id
        return "", ""

    def _is_fetch(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                owner, name = self._callee(sub)
                if name in ("urlopen", "urlretrieve") or (
                    name in ("get", "post", "request", "stream") and owner in self._FETCH_MODULES
                ):
                    return True
        return False

    def _carries(self, node: ast.AST | None) -> bool:
        """Whether an expression holds downloaded bytes, or names a downloaded file."""
        if node is None:
            return False
        if self._is_fetch(node):
            return True
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and (
                sub.id in self.tainted
                or (sub.id in self.constants and self._path(sub) in self.paths)
            ):
                return True
            text = self._name(sub) if isinstance(sub, ast.Attribute | ast.Constant) else ""
            if text and (text in self.tainted or self._path(sub) in self.paths):
                return True
        return False

    def _path(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.constants:
            return self.constants[node.id]
        return self._name(node)

    #: What each kind of node teaches `_walk` about names, by the method that learns it.
    _LEARN: ClassVar[dict[type[ast.AST], str]] = {
        ast.Assign: "_learn_assignment",
        ast.AnnAssign: "_learn_assignment",
        ast.AugAssign: "_learn_assignment",
        ast.With: "_learn_with",
        ast.AsyncWith: "_learn_with",
        ast.For: "_learn_loop",
        ast.AsyncFor: "_learn_loop",
        ast.FunctionDef: "_learn_function",
        ast.AsyncFunctionDef: "_learn_function",
    }

    def _walk(self) -> list[int]:
        hits: list[int] = []
        for node in ast.walk(self.tree):
            learner = self._LEARN.get(type(node))
            if learner is not None:
                getattr(self, learner)(node)
            if isinstance(node, ast.Call) and self._call(node):
                hits.append(node.lineno)
        return sorted(set(hits))

    def _learn_assignment(self, node: ast.Assign | ast.AnnAssign | ast.AugAssign) -> None:
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            for leaf in ast.walk(target):
                if not isinstance(leaf, ast.Name | ast.Attribute):
                    continue
                key = self._name(leaf)
                if isinstance(value, ast.Call) and self._callee(value)[1] == "open":
                    self._handle(key, value)
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    self.constants[key] = value.value
                if self._carries(value):
                    self.tainted.add(key)
                elif value is not None and self._names_a_path(value):
                    self.constants.setdefault(key, self._path(value))

    def _learn_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            if item.optional_vars is not None and self._carries(item.context_expr):
                self.tainted.add(self._name(item.optional_vars))
            self._file_handle(item)

    def _learn_loop(self, node: ast.For | ast.AsyncFor) -> None:
        if self._carries(node.iter):
            self.tainted.add(self._name(node.target))

    def _learn_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for ret in ast.walk(node):
            if isinstance(ret, ast.Return) and self._carries(ret.value):
                self.tainted.add(node.name)

    @staticmethod
    def _names_a_path(node: ast.AST) -> bool:
        return isinstance(node, ast.JoinedStr | ast.BinOp | ast.Call)

    def _file_handle(self, item: ast.withitem) -> None:
        """`with open(P, "wb") as f:` -- P is downloaded when f is written downloaded bytes."""
        expr = item.context_expr
        if (
            isinstance(expr, ast.Call)
            and self._callee(expr)[1] == "open"
            and item.optional_vars is not None
        ):
            self._handle(self._name(item.optional_vars), expr)

    def _handle(self, name: str, opened: ast.Call) -> None:
        """`f = open(P, "wb")`: remembers that writes to `f` land in P."""
        if not opened.args:
            return
        mode = opened.args[1] if len(opened.args) > 1 else None
        mode = next((k.value for k in opened.keywords if k.arg == "mode"), mode)
        if isinstance(mode, ast.Constant) and any(c in str(mode.value) for c in "wax"):
            self.constants[f"handle:{name}"] = self._path(opened.args[0])

    def _call(self, call: ast.Call) -> bool:
        """Records what the call writes, and reports whether it runs downloaded content."""
        owner, name = self._callee(call)
        args = [*call.args, *(k.value for k in call.keywords)]
        if name in ("exec", "eval", "compile") and not owner and call.args:
            return self._carries(call.args[0])
        if name == "urlretrieve" and len(call.args) > 1:
            self.paths.add(self._path(call.args[1]))
            return False
        if name in ("write", "writelines") and isinstance(call.func, ast.Attribute):
            handle = self.constants.get(f"handle:{self._name(call.func.value)}")
            if handle is not None and any(self._carries(a) for a in args):
                self.paths.add(handle)
            return False
        if name in ("write_bytes", "write_text") and isinstance(call.func, ast.Attribute):
            if any(self._carries(a) for a in args):
                self.paths.add(self._path(call.func.value))
                base = call.func.value
                if isinstance(base, ast.Call) and base.args:
                    self.paths.add(self._path(base.args[0]))
            return False
        if name in ("copyfileobj",) and len(call.args) > 1 and self._carries(call.args[0]):
            handle = self.constants.get(f"handle:{self._name(call.args[1])}")
            if handle is not None:
                self.paths.add(handle)
            return False
        if name in ("extractall", "extract", "unpack_archive") and (
            self._carries(call.func.value if isinstance(call.func, ast.Attribute) else None)
            or any(self._carries(a) for a in args)
        ):
            target = call.args[0] if call.args else None
            target = next(
                (k.value for k in call.keywords if k.arg in ("path", "extract_dir")), target
            )
            self.paths.add(self._path(target) if target is not None else ".")
            return False
        if (
            name in ("copy", "copyfile", "copy2", "move", "rename", "replace")
            and len(call.args) > 1
        ):
            if self._carries(call.args[0]):
                self.paths.add(self._path(call.args[1]))
            return False
        if name in ("clone_from", "clone_repository", "clone") and len(call.args) > 1:
            # `git.Repo.clone_from(url, path)`, pygit2, dulwich: a checkout is a download.
            self.paths.add(self._path(call.args[1]))
            return False
        cloned = self._git_clone_target(args)
        if cloned is not None:
            self.paths.add(cloned)
            return False
        if name == "chdir" and owner == "os" and call.args and self._runs_arg(call.args[0]):
            self.inside_download = True
            return False
        if name == "chmod" and owner in ("os", "") and len(call.args) > 1:
            # Making a downloaded file executable has one purpose.
            return self._executable_mode(call.args[1]) and self._runs_arg(call.args[0])
        if name in self._RUNNERS and owner in (
            "os",
            "subprocess",
            "runpy",
            "asyncio",
            "commands",
            "",
        ):
            if name == "run" and owner == "":
                return False
            return any(self._runs_arg(a) or self._shell_runs(a) for a in args)
        return False

    @staticmethod
    def _executable_mode(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return bool(node.value & 0o111)
        return any(
            isinstance(sub, ast.Attribute) and sub.attr.startswith(("S_IX", "S_IRWX"))
            for sub in ast.walk(node)
        )

    def _shell_runs(self, node: ast.AST) -> bool:
        """A command line handed to a shell that itself downloads and runs, or names a
        downloaded file: `os.system("curl -s URL | bash")`, `os.system("nohup /tmp/x &")`."""
        for sub in ast.walk(node):
            if not (isinstance(sub, ast.Constant) and isinstance(sub.value, str)):
                continue
            command = sub.value
            if " " not in command and "/" not in command:
                continue
            if ShellDownloads.runs(command):
                return True
            if any(
                p
                and len(p) > 3
                and re.search(r"(?:^|[\s;&|'\"(])" + re.escape(p) + r"(?:$|[\s;&|'\")])", command)
                for p in self.paths
            ):
                return True
        return False

    def _git_clone_target(self, args: list[ast.expr]) -> str | None:
        """Where `subprocess.run(["git", "clone", URL, DIR])` checks out to, if it is that."""
        for arg in args:
            if not isinstance(arg, ast.List | ast.Tuple):
                continue
            words = [self._path(e) for e in arg.elts]
            if len(words) > 2 and words[0].rsplit("/", 1)[-1] == "git" and words[1] == "clone":
                places = [w for w in words[2:] if w and not w.startswith("-")]
                if places:
                    repo = places[0].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                    return places[1] if len(places) > 1 else repo
        return None

    def _runs_arg(self, node: ast.AST) -> bool:
        if self._carries(node):
            return True
        if self.inside_download and isinstance(node, ast.List | ast.Tuple):
            # Run from inside a checkout: a relative file it is handed is the checkout's.
            for element in node.elts[1:]:
                path = self._path(element)
                if path and not path.startswith(("/", "-", "~")) and ("." in path or "/" in path):
                    return True
        for sub in ast.walk(node):
            path = self._path(sub)
            if path and any(
                path == p or (p and path.startswith(p.rstrip("/") + "/")) for p in self.paths
            ):
                return True
        return False


class DownloadFlow:
    """Whether a script runs what it downloads (`runs_download`)."""

    @staticmethod
    def runs_download(text: str, language: str | None) -> list[int] | None:
        """Lines where downloaded content is executed; None when the language is not read."""
        if language == "shell":
            return ShellDownloads.runs(text)
        if language == "python":
            return PythonDownloads.runs(text)
        return None
