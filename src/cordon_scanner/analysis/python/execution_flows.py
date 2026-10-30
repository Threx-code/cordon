"""What a Python file runs: a download started as a process, through helpers or on what it wrote;
code received and run; commands and the sketch of what they execute; written code later run; a
remote model's code loaded; decoded data handed to a parser.
"""

from __future__ import annotations

import ast
import base64
import posixpath
import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.pyfacts import (
    PRIMITIVES,
    PythonFacts,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.vocabulary import (
    BASE64_DECODERS,
    DOWNLOAD_TO,
    EXECUTABLE_NAME,
    FETCH_TOOL,
    INTERPRETER_NAMES,
    MODEL_COMMIT,
    PERSISTENCE_PATH,
    RUNNER_WORDS,
    SHELL_NAMES,
    SOURCE_FREE_CALLS,
    SOURCE_FREE_DOTTED,
    SOURCE_FREE_METHODS,
    SOURCE_FREE_NAMES,
    WRITE_METHODS,
    WRITTEN_CODE_MAX,
)
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Sequence


from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore


class ExecutionFlows(AnalyzerCore):
    """The Python analyser's execution flows: what a file downloads and runs."""

    def _source_free(self, node: ast.AST) -> bool:
        """Whether this expression is built only from literals and interpreter- or platform-provided
        constants (`sys.executable`, `__file__`, `os.sep`, ...), so nothing sourced -- decoded,
        downloaded, read or passed in -- can be part of its value. Fail-closed: a name not on the
        source-free list, an unresolved call, a subscript, `getattr`, a comprehension or a starred
        argument all make it False, which is what keeps `exec(b64decode(blob))` paired."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.JoinedStr):
            return all(self._source_free(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._source_free(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return self._source_free(node.left) and self._source_free(node.right)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return all(self._source_free(element) for element in node.elts)
        if isinstance(node, ast.Name):
            return node.id in SOURCE_FREE_NAMES
        if isinstance(node, ast.Attribute):
            return (self._dotted(node) or "") in SOURCE_FREE_DOTTED
        if isinstance(node, ast.Call):
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
            transform = (self._dotted(node.func) or "") in SOURCE_FREE_CALLS or (
                attr in SOURCE_FREE_METHODS
                and isinstance(node.func, ast.Attribute)
                and self._source_free(node.func.value)
            )
            if transform:
                return all(self._source_free(a) for a in node.args) and all(
                    self._source_free(k.value) for k in node.keywords
                )
        return False

    def _source_free_command(self, node: ast.Call) -> str | None:
        """The command a spawn or execute runs, folded to text with each source-free non-literal
        part shown as a neutral token, or None if any part is not source-free. The command is the
        first argument (an argv list is joined); `os.execv`/`execve`/`spawnv` also carry it in the
        second argument."""
        if not node.args:
            return None
        targets = [node.args[0]]
        if (self._dotted(node.func) or "") in ("os.execv", "os.execve", "os.spawnv") and len(
            node.args
        ) > 1:
            targets.append(node.args[1])
        parts: list[str] = []
        for target in targets:
            elements = target.elts if isinstance(target, ast.List | ast.Tuple) else [target]
            for element in elements:
                if not self._source_free(element):
                    return None
                parts.append(PythonFacts.constant(element) or "x")
        return " ".join(parts)

    def _socket_connect(self, tree: ast.AST) -> None:
        """A socket a file creates and then sends out on reaches the network; one it only binds and
        listens on does not. `.connect(...)` (a TCP client, in any argument form) and `.sendto(...)`
        (a UDP beacon, which never connects) both target a remote the code chose; a bind/listen/
        accept server uses neither. Socket creation alone is not egress (census D)."""
        calls = list(PythonSyntax.of(tree, ast.Call))
        if not any((r := self._resolve_callee(n)) and r[0] == "socket.socket" for n in calls):
            return
        for node in calls:
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("connect", "sendto"):
                self._record(Capability.EGRESS, node, "a created socket sends to a remote")

    def _egress_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        resolved = self._resolve_callee(node)
        return resolved is not None and PRIMITIVES.get(resolved[0]) is Capability.EGRESS

    @staticmethod
    def _word_key(word: str) -> str:
        """A command word as `_file_key` names a file: `"{out}"` is the variable `out`."""
        text = word.strip().strip("\"'")
        placeholder = re.fullmatch(r"\{(\w{1,80})\}", text)
        return f"name:{placeholder.group(1)}" if placeholder else text

    def _file_key(self, node: ast.AST) -> str | None:
        """A file named the same way twice: the literal path, the variable holding it, or a path
        built the same way each time (`os.getenv("APPDATA") + "\\u.exe"`)."""
        literal = PythonFacts.constant(node)
        if literal is None and isinstance(node, ast.Name):
            literal = self._strings.get(node.id) or f"name:{node.id}"
        if literal is None and isinstance(node, ast.BinOp | ast.JoinedStr | ast.Call):
            sketch = self._sketch(node)
            # Only a sketch that pins something down: a literal part, or a named variable's.
            if sketch and sketch.strip("{?}"):
                literal = ExecutionFlows._word_key(sketch)
        return literal or None

    def _downloaded_and_run(self, tree: ast.AST) -> None:
        """A process started on the file a download just wrote.

        `urlretrieve(URL, "/tmp/x.pyz")` then `subprocess.Popen(["python3", "/tmp/x.pyz"])` runs
        what the remote host served, as surely as `curl | sh` -- but each half alone is ordinary:
        installers download, and tools start processes. The link is the file both calls name, so
        that is what is checked: a spawn whose argument list names a file that was the target of a
        download, or that was opened for writing and written from a network response.
        """
        fetched: set[str] = set()
        downloaded: set[str] = set()
        for node in PythonSyntax.of(tree, ast.Assign, ast.With, ast.AsyncWith):
            if isinstance(node, ast.Assign) and self._egress_call(node.value):
                fetched.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.With | ast.AsyncWith):
                for item in node.items:
                    if self._egress_call(item.context_expr) and isinstance(
                        item.optional_vars, ast.Name
                    ):
                        fetched.add(item.optional_vars.id)
        # A download run as a command: `curl -o X`, `wget -O X`, `Invoke-WebRequest -OutFile X`.
        # And a command's captured output kept for later: `r = run(["curl", URL])`.
        fetched_output: set[str] = set()
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            command = self._command(resolved[1]) or ""
            download = DOWNLOAD_TO.search(command)
            if download:
                downloaded.add(ExecutionFlows._word_key(download.group("target")))
                # The download is the request: `curl.exe -L URL -o X` reaches the network
                # whatever the shell patterns make of the binary's name.
                self._record(Capability.EGRESS, node, f"{resolved[0]} downloads to a file")
        for node in PythonSyntax.of(tree, ast.Assign):
            if isinstance(node.value, ast.Call):
                spawned = self._resolve_callee(node.value)
                if spawned and PRIMITIVES.get(spawned[0]) is Capability.SPAWN:
                    command = self._command(spawned[1]) or ""
                    if FETCH_TOOL.match(command) and not DOWNLOAD_TO.search(command):
                        fetched_output.update(t.id for t in node.targets if isinstance(t, ast.Name))
        writers: dict[str, str] = {}
        for node in PythonSyntax.of(tree, ast.Call):
            callee = self._dotted(node.func)
            if (
                callee in ("urllib.request.urlretrieve", "urllib.urlretrieve")
                and len(node.args) > 1
            ):
                key = self._file_key(node.args[1])
                if key:
                    downloaded.add(key)
            elif callee == "open" and node.args:
                mode = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None
                key = self._file_key(node.args[0])
                if key and mode and ("w" in mode or "a" in mode):
                    writers[f"{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"] = key
        self._run_on_downloaded(tree, fetched, writers, downloaded)
        if not downloaded and not fetched_output:
            return
        executable_download = any(EXECUTABLE_NAME.search(key) for key in downloaded)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            call = resolved[1]
            if call.args and self._runs_one_of(call.args[0], downloaded):
                self._record(Capability.FETCH_EXEC, node, f"{resolved[0]} runs a downloaded file")
            elif call.args and executable_download and self._starts_an_executable(call):
                # A download saved as `main.exe`, moved, then started under its new name: the
                # rename breaks the link by path, not the shape -- a fetched executable, run.
                self._record(
                    Capability.FETCH_EXEC, node, f"{resolved[0]} runs a downloaded program"
                )
            elif call.args and self._evaluates_output(call.args[0], fetched_output):
                self._record(Capability.FETCH_EXEC, node, f"{resolved[0]} evaluates fetched text")

    def _run_on_downloaded(
        self, tree: ast.AST, fetched: set[str], writers: dict[str, str], downloaded: set[str]
    ) -> None:
        """A process started on a path a download wrote, directly or through a name bound to it."""
        for node in PythonSyntax.of(tree, ast.Call):
            # `with open(P, "wb") as out: out.write(response.read())` and
            # `open(P, "wb").write(r.content)`, where `response` or `r` came from a request.
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in WRITE_METHODS
                and node.args
            ):
                continue
            from_network = any(
                (isinstance(part, ast.Name) and part.id in fetched) or self._egress_call(part)
                for part in PythonSyntax.within(node.args[0], ast.Name, ast.Call)
            )
            if not from_network:
                continue
            target = node.func.value
            if isinstance(target, ast.Call) and self._dotted(target.func) == "open":
                key = writers.get(
                    f"{getattr(target, 'lineno', 0)}:{getattr(target, 'col_offset', 0)}"
                )
                if key:
                    downloaded.add(key)
            elif isinstance(target, ast.Name):
                downloaded.update(self._handles_opened_on(tree, target.id, writers))
                if node.func.attr in ("write_bytes", "write_text"):
                    # A `pathlib.Path` written directly: `helper.write_bytes(resp.content)`.
                    key = self._file_key(target)
                    if key:
                        downloaded.add(key)

    def _download_run_through_helpers(self, tree: ast.AST) -> None:
        """A download and its run, each in a helper, joined by the variable the caller hands both.

        `download_file(url, exe_path)` writes a response to its parameter, `run_exe(exe_path)`
        starts its parameter, and only the caller links them; `write_to_file(path, get_content())`
        writes what a fetcher returned. Every function is summarised once -- does it return
        fetched data, write fetched data (or a parameter) to a parameter's path, start a parameter
        -- and the call sites are joined through the name or literal they pass (review 98:
        utilitytools, pycolouring, both missed with every step in view).
        """
        functions = [
            node
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        if not functions:
            return

        fetchers: set[str] = set()

        for _ in range(2):
            for function in functions:
                local = self._network_names(function, fetchers)
                if any(
                    isinstance(n, ast.Return)
                    and n.value is not None
                    and self._from_network(n.value, local, fetchers)
                    for n in self._scope_walk(function)
                ):
                    fetchers.add(function.name)

        writers: dict[str, tuple[int, int | None]] = {}
        runners: dict[str, int] = {}
        self._helper_downloads(functions, fetchers, writers, runners)
        if not writers or not runners:
            return

        scopes: list[ast.AST] = [tree, *functions]
        downloaded: set[str] = set()
        for scope in scopes:
            local = self._network_names(scope, fetchers)
            for node in self._scope_walk(scope):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    continue
                spec = writers.get(node.func.id)
                if spec is None or len(node.args) <= spec[0]:
                    continue
                path_index, data_index = spec
                if data_index is not None and (
                    len(node.args) <= data_index
                    or not self._from_network(node.args[data_index], local, fetchers)
                ):
                    continue
                key = self._file_key(node.args[path_index])
                if key:
                    downloaded.add(key)
        if not downloaded:
            return
        for scope in scopes:
            for node in self._scope_walk(scope):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    continue
                argument = runners.get(node.func.id)
                if argument is None or len(node.args) <= argument:
                    continue
                if self._file_key(node.args[argument]) in downloaded:
                    self._record(
                        Capability.FETCH_EXEC,
                        node,
                        f"{node.func.id} runs the file a helper downloaded",
                    )

    def _helper_downloads(
        self,
        functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
        fetchers: set[str],
        writers: dict[str, tuple[int, int | None]],
        runners: dict[str, int],
    ) -> None:
        """Each helper that downloads to a path its caller hands it, and each that runs one."""
        for function in functions:
            names = PythonFacts.parameter_names(function)
            local = self._network_names(function, fetchers)
            handles: dict[str, ast.AST] = {}
            for node in self._scope_walk(function):
                if isinstance(node, ast.With):
                    for item in node.items:
                        path = PythonFacts.opened_path(item.context_expr)
                        if path is not None and isinstance(item.optional_vars, ast.Name):
                            handles[item.optional_vars.id] = path
                elif isinstance(node, ast.Assign):
                    path = PythonFacts.opened_path(node.value)
                    if path is not None:
                        handles.update(
                            {t.id: path for t in node.targets if isinstance(t, ast.Name)}
                        )
            for node in self._scope_walk(function):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in WRITE_METHODS
                    and node.args
                ):
                    continue
                target = node.func.value
                path = (
                    handles.get(target.id)
                    if isinstance(target, ast.Name)
                    else PythonFacts.opened_path(target)
                )
                if not isinstance(path, ast.Name) or path.id not in names:
                    continue
                data = node.args[0]
                data_param = next(
                    (
                        i
                        for i, n in enumerate(names)
                        if n in {x.id for x in PythonSyntax.within(data, ast.Name)}
                    ),
                    None,
                )
                if self._from_network(data, local, fetchers):
                    writers[function.name] = (names.index(path.id), None)
                elif data_param is not None:
                    writers[function.name] = (names.index(path.id), data_param)
            for node in PythonSyntax.of(function, ast.Call):
                resolved = self._resolve_callee(node)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                    continue
                call = resolved[1]
                if not call.args:
                    continue
                used = {x.id for x in PythonSyntax.within(call.args[0], ast.Name)}
                for index, name in enumerate(names):
                    if name in used:
                        runners[function.name] = index

    @staticmethod
    def _scope_walk(scope: ast.AST) -> list[ast.AST]:
        """`ast.walk(scope)`, in its order, walked once per scope: these readers asked for the same
        scope's walk up to ten times each (two passes of `_network_names` per call, per function,
        per round), 103 million node visits on one 5,000-module wheel (review 98, D2). Kept on the
        scope, so it goes with the tree."""
        cached: list[ast.AST] | None = scope.__dict__.get("_cordon_walk")
        if cached is None:
            cached = list(ast.walk(scope))
            scope.__dict__["_cordon_walk"] = cached
        return cached

    def _network_names(self, scope: ast.AST, fetchers: set[str]) -> set[str]:
        local: set[str] = set()
        assignments = [node for node in self._scope_walk(scope) if isinstance(node, ast.Assign)]
        for _ in range(2):
            for node in assignments:
                if self._from_network(node.value, local, fetchers):
                    local |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        return local

    def _from_network(self, expr: ast.AST, local: set[str], fetchers: set[str]) -> bool:
        for part in PythonSyntax.within(expr, ast.Name, ast.Call):
            if isinstance(part, ast.Name) and part.id in local:
                return True
            if isinstance(part, ast.Call):
                if self._egress_call(part):
                    return True
                if isinstance(part.func, ast.Name) and part.func.id in fetchers:
                    return True
        return False

    def _received_and_run(self, tree: ast.AST) -> None:
        """Code or a command that arrived over the network, executed.

        `exec(urlopen(C2).read())` and a socket loop that hands `conn.recv(1024)` to
        `subprocess.run(..., shell=True)` run whatever the far end sends: the first is a dropper
        with no file between the fetch and the run, the second a remote shell. The link is the
        value: a name bound from a request or a socket read, or from an expression over one,
        reaching `exec`/`eval`/`compile` or a process start as its command.

        `.recv` counts only with a size argument, which is the socket's signature -- a
        multiprocessing pipe's `recv()` takes none and returns objects from a local process.
        """

        def received(node: ast.AST) -> bool:
            """The value IS what arrived, not a command built around it: an f-string, `+`, `%`
            or `.format` that wraps a fetched value (`f"git checkout {sha}"`) passes it as data."""
            if any(
                isinstance(part, ast.JoinedStr)
                or (isinstance(part, ast.BinOp) and isinstance(part.op, ast.Add | ast.Mod))
                or (isinstance(part, ast.Attribute) and part.attr == "format")
                for part in PythonSyntax.within(node, ast.JoinedStr, ast.BinOp, ast.Attribute)
            ):
                return False
            for part in PythonSyntax.within(node, ast.Name, ast.Call):
                if isinstance(part, ast.Name) and part.id in tainted:
                    return True
                if self._egress_call(part):
                    return True
                if (
                    isinstance(part, ast.Call)
                    and isinstance(part.func, ast.Attribute)
                    and part.func.attr in ("recv", "recvfrom")
                    and part.args
                ):
                    return True
            return False

        tainted: set[str] = set()
        assignments = [
            node
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None
        ]
        for _ in range(4):
            before = len(tainted)
            for assignment in assignments:
                targets = (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                )
                if assignment.value is not None and received(assignment.value):
                    tainted.update(t.id for t in targets if isinstance(t, ast.Name))
            if len(tainted) == before:
                break
        for node in PythonSyntax.of(tree, ast.Call):
            if not node.args:
                continue
            resolved = self._resolve_callee(node)
            if resolved is None:
                continue
            capability = PRIMITIVES.get(resolved[0])
            command = resolved[1].args[0] if resolved[1].args else None
            if command is None or not received(command):
                continue
            if capability is Capability.EXECUTE:
                self._record(
                    Capability.FETCH_EXEC,
                    node,
                    f"{resolved[0]} runs code received over the network",
                )
            elif capability is Capability.SPAWN and not isinstance(command, ast.List | ast.Tuple):
                # A command string from the network, not an argument list naming a program: `run(
                # ["git", "clone", url])` passes a fetched URL as data.
                self._record(
                    Capability.FETCH_EXEC,
                    node,
                    f"{resolved[0]} runs a command received over the network",
                )

    def _starts_an_executable(self, call: ast.Call) -> bool:
        text = self._command(call) or PythonFacts.constant(call.args[0]) or ""
        return EXECUTABLE_NAME.search(text) is not None

    def _runs_remote_model_code(self, node: ast.Call) -> bool:
        """`from_pretrained(<hub id>, trust_remote_code=True)` and every other call that takes the
        switch -- `pipeline`, `load_dataset`: download the Python the model or dataset repository's
        owner wrote, and run it.

        Not when `revision=` pins a commit (forty hex characters): the code is then the code that
        was reviewed, not whatever the repository holds today. Not for a path written as one
        (`./`, `../`, `/`): that is the project's own checkout."""
        if not any(
            k.arg == "trust_remote_code"
            and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in node.keywords
        ):
            return False
        revision = next(
            (PythonFacts.constant(k.value) for k in node.keywords if k.arg == "revision"), None
        )
        if revision and MODEL_COMMIT.fullmatch(revision):
            return False
        source = PythonFacts.constant(node.args[0]) if node.args else None
        source = source or next(
            (
                PythonFacts.constant(k.value)
                for k in node.keywords
                if k.arg in ("pretrained_model_name_or_path", "model", "path")
            ),
            None,
        )
        return not (source and source.startswith(("./", "../", "/")))

    def _opened_for_persistence(self, node: ast.Call) -> None:
        """`open(<a shell profile, LaunchAgent, crontab or systemd user unit>, "a")`.

        The pattern tier reads paths written out; one assembled at runtime -- bo3to builds
        `/home/<user>/.profile` from character codes and appends to it for every user in
        `/etc/passwd` -- is only legible once folded.
        """
        mode = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None
        mode = mode or next(
            (PythonFacts.constant(k.value) for k in node.keywords if k.arg == "mode"), None
        )
        if not mode or not any(flag in mode for flag in "wa"):
            return
        path = self._sketch(node.args[0])
        if path and PERSISTENCE_PATH.search(path):
            self._record(Capability.PERSIST, node, f"open: {path[-60:]}")

    def _evaluates_output(self, argv: ast.AST, fetched: set[str]) -> bool:
        """`run(["node", "-e", r.stdout])` where `r` holds a download's output."""
        if not fetched or not isinstance(argv, ast.List | ast.Tuple) or len(argv.elts) < 3:
            return False
        program = posixpath.basename(PythonFacts.constant(argv.elts[0]) or "").lower()
        flag = PythonFacts.constant(argv.elts[1]) or ""
        code = argv.elts[2]
        source = code.value if isinstance(code, ast.Attribute) else code
        return (
            program in INTERPRETER_NAMES
            and flag in ("-e", "-c", "--eval", "-Command", "-command", "/c")
            and isinstance(source, ast.Name)
            and source.id in fetched
        )

    def _runs_one_of(self, argv: ast.AST, files: set[str]) -> bool:
        """Whether this command runs one of these files: as the program, or as the script an
        interpreter is handed. `tar xzf tool.tgz` names a downloaded file and runs nothing of it."""
        if isinstance(argv, ast.List | ast.Tuple):
            # `str(path)` and `os.fspath(path)` name the same file as `path`.
            elements = [
                e.args[0]
                if isinstance(e, ast.Call)
                and self._dotted(e.func) in ("str", "os.fspath")
                and len(e.args) == 1
                else e
                for e in argv.elts
            ]
            texts: list[str | None] = [
                self._dotted(e)
                if isinstance(e, ast.Attribute)
                # A name bound to one literal is that literal, as `_file_key` reads it.
                else (self._strings.get(e.id) or self._sketch(e) or f"{{{e.id}}}")
                if isinstance(e, ast.Name)
                else self._sketch(e)
                for e in elements
            ]
        else:
            text = self._sketch(argv)
            if text is None:
                return self._file_key(argv) in files
            texts = list(text.split())
        return self._words_run(texts, files, depth=0)

    def _words_run(self, words: Sequence[str | None], files: set[str], depth: int) -> bool:
        """Whether a command, as words, runs one of these files."""
        present = [w for w in words if w and w.strip("\"'")]
        if not present or depth > 2:
            return False
        # `./tool` is `tool` run from here: the download was written as `tool`.
        first = present[0].strip("\"'")
        if ExecutionFlows._word_key(first) in files or (
            first.startswith("./") and ExecutionFlows._word_key(first[2:]) in files
        ):
            return True
        program = posixpath.basename(present[0].strip("\"'")).lower()
        if program in SHELL_NAMES:
            # `powershell -Command "<cmd>"`, `sh -c "<cmd>"`: the command is more words.
            for index, word in enumerate(present[1:], start=1):
                if word.lower() in ("-c", "-command", "/c"):
                    return self._words_run(" ".join(present[index + 1 :]).split(), files, depth + 1)
        if program == "sys.executable" or program in INTERPRETER_NAMES or program in RUNNER_WORDS:
            script = next((w for w in present[1:] if not w.startswith("-")), None)
            if script is None:
                return False
            script = script.strip("\"'")
            return ExecutionFlows._word_key(script) in files or (
                script.startswith("./") and ExecutionFlows._word_key(script[2:]) in files
            )
        return False

    def _handles_opened_on(self, tree: ast.AST, handle: str, writers: dict[str, str]) -> set[str]:
        """The files a `with open(...) as <handle>` in this tree opened for writing."""
        keys: set[str] = set()
        for node in PythonSyntax.of(tree, ast.With, ast.AsyncWith):
            for item in node.items:
                expression = item.context_expr
                if (
                    isinstance(item.optional_vars, ast.Name)
                    and item.optional_vars.id == handle
                    and isinstance(expression, ast.Call)
                ):
                    key = writers.get(
                        f"{getattr(expression, 'lineno', 0)}:{getattr(expression, 'col_offset', 0)}"
                    )
                    if key:
                        keys.add(key)
        return keys

    def _written_text(self, node: ast.AST) -> str | None:
        """The text a write puts on disk, when the file states it: a literal, or base64 of one.

        `f.write(base64.b64decode(PAYLOAD))` with `PAYLOAD` a literal is decoded here -- decoding,
        never running -- because a payload kept encoded until the moment it is written is the
        ordinary form of the drop-and-run step, and its contents are the evidence.
        """
        if isinstance(node, ast.IfExp):
            # `exec("s.run('s.exe')" if sys.platform == "win32" else "pass")`: both branches are
            # code the file can run, and the one doing something is the one that matters.
            branches = [self._written_text(node.body), self._written_text(node.orelse)]
            return max((b for b in branches if b), key=len, default=None)
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bytes):
                return value.decode("utf-8", "replace")
            return value if isinstance(value, str) else None
        if (
            not isinstance(node, ast.Call)
            or not node.args
            or self._dotted(node.func) not in BASE64_DECODERS
        ):
            # A value the folder can compute -- `"".join(map(chr, [...]))` -- is still a literal.
            return PythonFacts.constant(node)
        argument = node.args[0]
        encoded = (
            self._strings.get(argument.id)
            if isinstance(argument, ast.Name)
            else PythonFacts.constant(argument)
        )
        if isinstance(argument, ast.Constant) and isinstance(argument.value, bytes):
            encoded = argument.value.decode("ascii", "replace")
        if not encoded or len(encoded) > WRITTEN_CODE_MAX * 2:
            return None
        decode = (
            base64.urlsafe_b64decode
            if "urlsafe" in (self._dotted(node.func) or "")
            else base64.b64decode
        )
        try:
            return decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None


__all__ = ["ExecutionFlows"]
