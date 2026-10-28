"""When the code a capability hit sits in runs: on load, or only when someone asks for it.

An install hook runs a package's load path on every consumer's machine; a function nothing on that path
calls runs only when a user or program calls it. These are the capability detector's answers to which
one a hit is in: a fetch-and-run behind a request, a Go function reached from `init()`, a load-time
initialiser in Go, Java or another compiled language, and the Python and JavaScript function bodies
the load path defers."""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import (
    ScanContext,
)
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.foundation.models import (
    Capability,
)

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class LoadPath:
    """Questions about whether the code a hit sits in runs on load."""

    #: A download written to an executable and started, as one construct: a command line in
    #: JavaScript, or a batch file's download-then-`start`. Not `DOWNLOAD_THEN_RUN`, the data-flow
    #: reading of an HTTP download later spawned -- which is how a legitimate extension fetches its
    #: own language server or CLI.
    DOWNLOAD_RUN_CONSTRUCTS = frozenset(
        {"CAP.JS.COMMAND_FETCH_RUN.001", "CAP.BAT.FETCH_EXEC.001", "CAP.SH.FETCH_EXEC.001"}
    )

    @staticmethod
    def runs_a_downloaded_file(hits: list[CapabilityHit]) -> bool:
        return any(hit.rule_id in LoadPath.DOWNLOAD_RUN_CONSTRUCTS for hit in hits)

    RUNNERS = frozenset(
        {
            "atexit.register",
            "Thread",
            "Timer",
            "Process",
            "signal.signal",
            "start_new_thread",
            "execute",
        }
    )

    DEFINITION_TIME_DUNDERS = frozenset(
        {"__init_subclass__", "__set_name__", "__class_getitem__", "__prepare__", "__new__"}
    )

    SCRIPT_LANGUAGES_RUN_BY_HAND = frozenset(
        {"shell", "powershell", "batch", "dockerfile", "makefile"}
    )

    _SKILL_SCRIPT = re.compile(
        r"(?:^|/)skills/[^/\n]{1,200}/[^\n]{0,400}\.(?:py|js|mjs|cjs|ts|sh|bash|ps1|rb)$"
    )

    @staticmethod
    def skill_script(path: str, ctx: ScanContext | None) -> bool:
        """A script an agent skill ships: under a `skills/<name>/` folder, or beside or below a
        `SKILL.md` -- a skill unpacked on its own, from a marketplace or an archive, has no
        `skills/` parent and is still run by the agent whenever the skill is invoked."""
        if LoadPath._SKILL_SCRIPT.search(path.rpartition("!")[2]):
            return True
        if ctx is None or not path.lower().endswith(LoadPath.SKILL_SCRIPT_SUFFIXES):
            return False
        parts = path.split("/")[:-1]
        return any(
            "/".join([*parts[:depth], "SKILL.md"]) in ctx.tree_paths
            for depth in range(len(parts), max(-1, len(parts) - 4), -1)
        )

    SKILL_SCRIPT_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".rb")

    ON_REQUEST_REASONS = (
        "a script a person runs, not code that runs on its own",
        "function bodies that run only when called",
        "compiled code that runs when the program is run, not when it is imported",
    )

    COMPILED_LANGUAGES = frozenset(
        {"go", "java", "kotlin", "csharp", "rust", "swift", "c", "cpp", "scala"}
    )

    _LOAD_TIME_INITIALISER = re.compile(
        r"^[ \t]{0,8}func[ \t]+init[ \t]*\([ \t]*\)[ \t]*\{|^[ \t]{0,40}static[ \t]*\{"
        r"|^[ \t]{0,40}static[ \t]+[A-Z]\w{0,80}[ \t]*\([ \t]*\)[ \t]*\{"
        # C and C++ library constructors, and Rust's `#[ctor]`: run when the library is loaded.
        r"|__attribute__[ \t]{0,4}\(\([ \t]{0,4}constructor[^{;]{0,300}\{"
        r"|#\[ctor\][ \t\r\n]{0,40}(?:pub[ \t]{1,4})?(?:unsafe[ \t]{1,4})?fn[ \t]+\w{1,80}[ \t]*\([^)]{0,200}\)[^{;]{0,100}\{",
        re.MULTILINE,
    )

    _JS_BODY_OPENER = re.compile(
        r"(?:\bfunction\b[^{;]{0,300}|=>[ \t]{0,8}|^[ \t]{0,40}(?:(?:async|static|get|set|public|private|protected)"
        r"[ \t]{1,8}){0,3}(?!(?:if|for|while|switch|catch|with|return|else|do|try)\b)[A-Za-z_$#][\w$]{0,80}"
        r"[ \t]{0,8}\([^)\n]{0,300}\)[^{;\n]{0,200})\{",
        re.MULTILINE,
    )

    @staticmethod
    def run_on_request(
        content: FileContent,
        language: str | None,
        hits: list[CapabilityHit],
        matched: tuple[Capability, ...],
        ctx: ScanContext | None = None,
    ) -> str:
        """Why this fetch-and-run happens only when someone asks for it, or "" if it does not.

        A shell script, Dockerfile or Makefile outside any hook runs when a person runs it. In
        Python and JavaScript, the question is whether every hit is inside a function body: a
        module's top level runs on import, a function's body when it is called.
        """
        if LoadPath.skill_script(content.path, ctx):
            # A skill's bundled script is run by the agent whenever the skill is invoked -- as a
            # program, so its module-level calls run too. Nobody is asked first.
            return ""
        if SourcePaths.is_editor_extension(content.path) and (
            language in LoadPath.SCRIPT_LANGUAGES_RUN_BY_HAND
            or LoadPath.runs_a_downloaded_file(hits)
        ):
            # A script inside an extension -- a bundled `.bat` -- is run by the extension, not by a
            # person; and a download that is run, in one construct, is not lowered for sitting in a
            # function. The weaker combinations in an extension's code keep the ordinary lowering:
            # spawning, decoding and a request are what remote-development tools do all day
            # (Remote WSL, Codespaces, APKLab were blocked for it).
            return ""
        if language in LoadPath.SCRIPT_LANGUAGES_RUN_BY_HAND:
            return LoadPath.ON_REQUEST_REASONS[0]
        if language in LoadPath.COMPILED_LANGUAGES:
            if LoadPath._in_load_time_initialiser(content, hits, matched):
                return ""
            if language == "go" and LoadPath.in_go_load_path(content, hits, matched):
                return ""
            return LoadPath.ON_REQUEST_REASONS[2]
        offsets = [
            h.byte_start
            for h in hits
            if h.capability in matched
            or h.capability is Capability.DECODE
            or h.rule_id
            in (
                "AST.PY.IDENTITY_SENT",
                "AST.PY.ENVIRONMENT_SENT",
                "AST.PY.SECRET_SENT",
                "FLOW.JS.SECRET_SENT",
                "FLOW.JS.IDENTITY_SENT",
                "FLOW.JS.ENVIRONMENT_SENT",
            )
        ]
        if not offsets:
            return ""
        spans = LoadPath._function_body_spans(content, language)
        if spans and all(any(start <= at < end for start, end in spans) for at in offsets):
            return LoadPath.ON_REQUEST_REASONS[1]
        return ""

    #: A function or method declaration. Indented too: gofmt never indents one, so an indented
    #: `func` is a file written not to be read by tools anchored at the margin (review 98:
    #: `boltdb-go/bolt` 1.3.1 hid its command channel in `\tfunc ApiInit() {`).
    GO_FUNC = re.compile(
        r"^[ \t]*func[ \t]+(?:\([^)\n]{0,120}\)[ \t]*)?([A-Za-z_]\w{0,80})[ \t]*"
        r"\([^)\n]{0,300}\)[^{\n]{0,200}\{",
        re.MULTILINE,
    )

    _GO_CALL = re.compile(r"\b([A-Za-z_]\w{0,80})[ \t]*\(")

    @staticmethod
    def in_go_load_path(
        content: FileContent, hits: list[CapabilityHit], matched: tuple[Capability, ...]
    ) -> bool:
        """Whether a matched hit is in a Go function that runs when the package is imported.

        `init()` runs on import, and so does every package-level `var` initialiser: `var _ =
        setup()` calls `setup` before `main`, or before the importer's own code. The malicious Go
        typosquats of 2025 ran their payload as `var DdlXrFDZ = eGtROk()`. A function is on the
        load path if `init` or an initialiser calls it, directly or through other functions in
        the file; a hit inside one keeps its full weight.
        """
        text = content.text
        bodies: dict[str, tuple[int, int]] = {}
        declarations: list[tuple[int, int]] = []
        for found in LoadPath.GO_FUNC.finditer(text):
            depth, index = 1, found.end()
            limit = min(len(text), index + 200_000)
            while index < limit and depth:
                depth += text[index] == "{"
                depth -= text[index] == "}"
                index += 1
            bodies.setdefault(found.group(1), (found.end(), index))
            declarations.append((found.start(), index))
        if not bodies:
            return False
        # Package-level code: everything outside function declarations, signature included, so
        # a function's own name in `func name(` is not read as a call from an initialiser.
        outside: list[str] = []
        cursor = 0
        for start, end in sorted(declarations):
            outside.append(text[cursor:start])
            cursor = end
        outside.append(text[cursor:])
        top_level = "".join(outside)
        roots = {m.group(1) for m in LoadPath._GO_CALL.finditer(top_level)}
        reached = {"init"} | (roots & bodies.keys())
        frontier = list(reached)
        while frontier:
            name = frontier.pop()
            span = bodies.get(name)
            if span is None:
                continue
            for call in LoadPath._GO_CALL.finditer(text, span[0], span[1]):
                callee = call.group(1)
                if callee in bodies and callee not in reached:
                    reached.add(callee)
                    frontier.append(callee)
        # Byte offsets of hits, mapped to text offsets via the line table.
        starts = content.line_starts
        line_offsets: list[int] = [0]
        for line in text.splitlines(keepends=True):
            line_offsets.append(line_offsets[-1] + len(line))
        from bisect import bisect_right

        for hit in hits:
            if hit.capability not in matched:
                continue
            row = bisect_right(starts, hit.byte_start) - 1
            at = line_offsets[min(row, len(line_offsets) - 1)]
            for name in reached:
                span = bodies.get(name)
                if span and span[0] <= at < span[1]:
                    return True
        return False

    @staticmethod
    def _in_load_time_initialiser(
        content: FileContent, hits: list[CapabilityHit], matched: tuple[Capability, ...]
    ) -> bool:
        """Whether any matched hit sits inside a Go `init()`, a Java static block or a C# static
        constructor -- found by brace matching from the opener, bounded."""
        text = content.raw
        offsets = [h.byte_start for h in hits if h.capability in matched]
        if not offsets:
            return False
        for opener in LoadPath._LOAD_TIME_INITIALISER.finditer(content.text):
            start = len(content.text[: opener.end()].encode("utf-8"))
            depth, index, limit = 1, start, min(len(text), start + 200_000)
            while index < limit and depth:
                byte = text[index]
                depth += byte == 0x7B
                depth -= byte == 0x7D
                index += 1
            if any(start <= at < index for at in offsets):
                return True
        return False

    @staticmethod
    def _function_body_spans(content: FileContent, language: str | None) -> list[tuple[int, int]]:
        """Byte spans of the function bodies nothing on this file's load path reaches.

        A body counts as run on load when code that runs on load names its function -- called,
        or handed to `atexit.register` or a `Thread` -- or, transitively, when such a body does.
        `def _x(): ...` followed by `_x()` at module level is top-level code with one extra line.
        A Python decorator defined in the same file may call what it decorates and makes the body
        count; an imported one (`@app.route`, `@patch`) registers it.
        """
        if language == "python":
            return LoadPath._python_deferred_spans(content)
        if language in ("javascript", "typescript"):
            return LoadPath._js_deferred_spans(content)
        return []

    @staticmethod
    def _python_deferred_spans(content: FileContent) -> list[tuple[int, int]]:
        try:
            tree = PythonSyntax.shared(content.text)
        except (SyntaxError, ValueError, RecursionError):
            return []
        functions = [
            node
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        if not functions or len(functions) > 5_000:
            return []

        # A decorator defined here that calls what it decorates in its own body -- not in a
        # wrapper it returns -- runs the function at definition: `def now(f): f(); return f`.
        # One that registers or wraps it (`gh_patch`, `functools.wraps`) runs nothing.
        def calls_its_argument(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            params = [a.arg for a in node.args.args[:1]]
            if not params:
                return False
            pending: list[ast.AST] = list(node.body)
            while pending:
                current = pending.pop()
                if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                    continue
                if (
                    isinstance(current, ast.Call)
                    and isinstance(current.func, ast.Name)
                    and current.func.id == params[0]
                ):
                    return True
                pending.extend(ast.iter_child_nodes(current))
            return False

        local = {node.name for node in functions if calls_its_argument(node)}

        def names_in(nodes: Sequence[ast.AST]) -> set[str]:
            found: set[str] = set()
            for root in nodes:
                for node in PythonSyntax.nodes(root):
                    if isinstance(node, ast.Name):
                        found.add(node.id)
                    elif isinstance(node, ast.Attribute):
                        found.add(node.attr)
            return found

        def decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
            return names_in(list(node.decorator_list))

        def run_names(nodes: Sequence[ast.AST]) -> set[str]:
            """Names these nodes call, or hand to something that runs them unprompted.

            Handing a function to a registry -- `add_constructor(tag, f)`, `app.route(f)` --
            is not running it: a YAML loader's unsafe-tag handler runs when somebody loads a
            document that names the tag.
            """
            found: set[str] = set()
            for root in nodes:
                for node in PythonSyntax.of(root, ast.Call):
                    func = node.func
                    callee = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else ""
                    )
                    found.add(callee)
                    owner = (
                        func.value.id
                        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                        else ""
                    )
                    if callee in LoadPath.RUNNERS or f"{owner}.{callee}" in LoadPath.RUNNERS:
                        for argument in [*node.args, *(k.value for k in node.keywords)]:
                            if isinstance(argument, ast.Name):
                                found.add(argument.id)
                            elif isinstance(argument, ast.Attribute):
                                found.add(argument.attr)
            return found

        nested = {
            id(inner)
            for outer in functions
            for inner in PythonSyntax.nodes(outer)
            if inner is not outer
        }
        from cordon_scanner.engine.reachability import CallReachability

        on_load: list[ast.AST] = []
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Module | ast.ClassDef):
                on_load.extend(
                    child
                    for child in node.body
                    if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                    # A module's `if __name__ == "__main__":` block runs when the file is
                    # executed as a script, which is a request, not a load.
                    and not (isinstance(node, ast.Module) and CallReachability.is_main_guard(child))
                )
        # An instance method's dunder -- `__init__`, `__call__`, `__enter__` -- runs when the class
        # is instantiated, and that is a call like any other: xgboost's `RabitTracker.__init__`
        # binds a socket for a distributed job, and nothing builds a tracker on import. Dunders
        # that run when a class is defined or subclassed, and module-level `__getattr__`, still
        # count as run on load. A class used as another's base keeps its dunders, since the
        # subclass may be what is built.
        owner_of: dict[int, str] = {}
        bases_used: set[str] = set()
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.ClassDef):
                bases_used |= names_in(list(node.bases))
                for child in node.body:
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                        owner_of[id(child)] = node.name

        def dunder(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            return node.name.startswith("__") and node.name.endswith("__")

        def on_instance(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            return (
                dunder(node)
                and id(node) in owner_of
                and node.name not in LoadPath.DEFINITION_TIME_DUNDERS
                and owner_of[id(node)] not in bases_used
            )

        reached: set[int] = set()
        for node in functions:
            if (dunder(node) and not on_instance(node)) or decorator_names(node) & local:
                reached.add(id(node))
        referenced = run_names(on_load) | {
            name for node in functions if id(node) in reached for name in run_names(node.body)
        }
        changed = True
        while changed:
            changed = False
            for node in functions:
                if id(node) in reached:
                    continue
                trigger = owner_of[id(node)] if on_instance(node) else node.name
                if trigger in referenced:
                    reached.add(id(node))
                    referenced |= run_names(node.body)
                    changed = True
        starts = [0]
        for line in content.raw.split(b"\n"):
            starts.append(starts[-1] + len(line) + 1)
        spans = []
        for node in functions:
            if id(node) in reached or id(node) in nested:
                continue
            first, last = node.body[0].lineno, node.end_lineno or node.body[-1].lineno
            if last < len(starts):
                spans.append((starts[first - 1], starts[last]))
        return spans

    @staticmethod
    def _js_deferred_spans(content: FileContent) -> list[tuple[int, int]]:
        # The pattern runs over text and the hits are byte offsets, which agree only on ASCII
        # source. Anything else finds no bodies, and the finding keeps its severity.
        if not content.raw.isascii():
            return []
        text = content.raw
        bodies: list[tuple[int, int, str]] = []
        for match in LoadPath._JS_BODY_OPENER.finditer(content.text):
            open_brace = match.end() - 1
            named = re.search(
                r"([A-Za-z_$][\w$]{0,80})[ \t]{0,8}(?:=[^=>]{0,80}|\()", match.group(0)
            )
            name = named.group(1) if named and named.group(1) != "function" else ""
            depth = 0
            for index in range(open_brace, min(len(text), open_brace + 200_000)):
                byte = text[index]
                if byte == 0x7B:
                    depth += 1
                elif byte == 0x7D:
                    depth -= 1
                    if depth == 0:
                        # `(async function go() { ... })()` and `(() => { ... })()` run as the
                        # file loads: an immediately-invoked body is top-level code.
                        after = text[index + 1 : index + 16].lstrip()
                        if not (
                            after.startswith(b"(")
                            or (after[:1] == b")" and after[1:].lstrip().startswith(b"("))
                        ):
                            bodies.append((open_brace, index, name))
                        break
        # Fixpoint: a body is reached when its name appears outside every unreached body.
        unreached = [b for b in bodies if b[2]]
        changed = True
        while changed:
            changed = False
            for body in list(unreached):
                pattern = re.compile(rf"(?<![\w$]){re.escape(body[2])}(?![\w$])")
                for occurrence in pattern.finditer(content.text):
                    at = occurrence.start()
                    inside = any(start <= at <= end for start, end, _ in unreached)
                    preceding = content.text[max(0, at - 40) : at].rstrip()
                    following = content.text[occurrence.end() : occurrence.end() + 40].lstrip()
                    # Called, or handed to something that calls it (`setTimeout(setup)`,
                    # `process.on("exit", setup)`). Exporting a function runs nothing.
                    used = following.startswith("(") or (
                        preceding.endswith(("(", ",")) and following.startswith((")", ","))
                    )
                    if not inside and used and not preceding.endswith("function"):
                        unreached.remove(body)
                        changed = True
                        break
        return [(start, end) for start, end, _ in unreached]


__all__ = ["LoadPath"]
