"""JavaScript that runs and that no reader can take to its end: a content gap, or said (BP-15-19).

The Python side decides this for every file that runs when a package is installed or imported
(`analysis/python/unparsed_source.py`): a file that does not parse is a gap when it names anything that
could run its pieces, and `SOURCE.BROKEN` (said, not a gap) when it names nothing. The JavaScript readers
take tokens, not a syntax tree, so a file whose brackets do not close was read as far as it went and
passed without a word: an entry of 200,000 open parentheses was a complete scan.

```
  running files = what package.json names (main, bin, exports, the files its install scripts hand to node) + what those require, and a published
        │           package's import entries and install hooks
        ▼  its brackets do not close: 52 or more of them are wrong (a close of another kind, a close with nothing open, an open at the end)
  an act token anywhere in the file (eval, Function, require, import, child_process, a network, a decoder) ─► SOURCE.UNPARSED, a gap,
        │ no                                                                                                  and the running verdict
        ▼
  SOURCE.BROKEN, said: Node refuses the file when it is loaded, so nothing in it runs
```

A file the reader only has a prefix of (it was cut at the size cap) is not decided here: a prefix does not close, and a cut file is a recorded
fact of its own (`OPERATIONAL.FILE.TRUNCATED`). A file nothing runs -- a test, a template, an unused module -- is not reported.
"""

from __future__ import annotations

import json
import posixpath
import re
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.analysis.javascript.flow.vocabulary import _CLOSE, _OPEN
from cordon_scanner.analysis.javascript.js_eval import JsEval
from cordon_scanner.analysis.python.unparsed_source import Decision, UnparsedSource

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding

#: The files whose brackets are read here.
SUFFIXES: Final = (".js", ".mjs", ".cjs")


class JsUnparsed:
    #: What could run a file's pieces, or what a payload does: code from text, loading by name, decoding, processes, the network, vm and wasm.
    ACT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:eval|Function|require|import|child_process|exec|execSync|spawn\w*|fork|fetch|XMLHttpRequest|WebSocket|"
        r"http|https|net|dgram|tls|dns|vm|WebAssembly|atob|btoa|Buffer|zlib|process|globalThis|Reflect)\b"
    )

    #: How many bracket errors a file may show and still be read as source. The tokenizer is not a parser: a regular expression holding a bracket, a text in
    #: JSX, a type argument or a shebang puts it off by a few. Measured on 52 flagged files of 36 legitimate units (npm and MCP, dev half): 1 to 31 errors
    #: each; then over every running JavaScript file of the legitimate lists (18,166 files, 435 units): 17,976 with none, 190 with 1 to 26 (1: 13, 2-3: 46,
    #: 4-7: 71, 8-15: 48, 16-31: 12), the largest 26. Twice the largest is 52. The hostile inputs written for the tests are off by thousands.
    TOLERATED: ClassVar[int] = 52

    @staticmethod
    def runs_as_source(path: str, running: set[str]) -> bool:
        return path in running and path.endswith(SUFFIXES)

    @staticmethod
    def errors(tokens: list[Any]) -> int:
        """How many brackets do not close, counted with recovery: a close that matches nothing open is one error and is skipped; a close of another
        kind pops to its own open when one is open (each open it skips is one error); what is still open at the end is one error each."""
        stack: list[str] = []
        count = 0
        for token in tokens:
            if token.kind != "punct":
                continue
            if token.value in _OPEN:
                stack.append(_OPEN[token.value])
            elif token.value in _CLOSE:
                if token.value in stack:
                    while stack[-1] != token.value:
                        stack.pop()
                        count += 1
                    stack.pop()
                else:
                    count += 1
        return count + len(stack)

    @staticmethod
    def closes(text: str) -> bool | None:
        """Whether the brackets close, give or take what the reader itself gets wrong: fewer than `TOLERATED` errors. None when the reader's own
        bound was reached (no verdict: a gap)."""
        try:
            tokens = JsEval.tokens(text, templates=True)
        except (RecursionError, MemoryError, ValueError):
            return None
        return JsUnparsed.errors(tokens) < JsUnparsed.TOLERATED

    @staticmethod
    def decide(text: str) -> Decision:
        """`parses` (every bracket closes), `gap` (it does not, or the reader's bound was reached, and something could run its pieces), or
        `broken` (it does not close and names nothing that could)."""
        closed = JsUnparsed.closes(text)
        if closed is True:
            return Decision("parses")
        if closed is None or JsUnparsed.ACT.search(text) is not None:
            return Decision("gap")
        return Decision("broken")

    @staticmethod
    def broken(path: str) -> Finding:
        from cordon_scanner.foundation.results import OperationalFinding

        return OperationalFinding.build(
            path=path,
            rule_id=UnparsedSource.BROKEN,
            message=(
                f"{path} is loaded or run, and its brackets do not close: Node refuses the file when it is loaded, "
                "so nothing in it runs. It names nothing that could run its pieces."
            ),
            remediation="Fix the file, or drop it from the package.",
        )


class JsRunning:
    """The JavaScript files that run, read from the package's own manifest: what `package.json` names (main, bin, exports) and the files its
    install scripts hand to node, and the files those require by a relative path (a cap on how many). This is the directory route, a cloned
    repository or an MCP server checked out from git, where no published-package context says what runs."""

    LIFECYCLE: ClassVar[tuple[str, ...]] = (
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepublish",
        "preprepare",
        "postprepare",
    )
    SCRIPT_FILE: ClassVar[re.Pattern[str]] = re.compile(
        r"""\bnode(?:js)?\s+(?:--?[\w=.-]+\s+)*['"]?([^\s'"&|;<>]+\.(?:c|m)?js)\b"""
    )
    RELATIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?:\brequire\s*\(|\bimport\s*\(|\bfrom\s+|\bimport\s+)\s*['"](\.{1,2}/[^'"\n]{1,200})['"]"""
    )
    MAX_FILES: ClassVar[int] = 200

    @staticmethod
    def named(document: object) -> list[str]:
        """The file names a manifest gives as what runs."""
        if not isinstance(document, dict):
            return []
        found: list[str] = []
        main = document.get("main")
        found.append(main if isinstance(main, str) and main else "index.js")
        bins = document.get("bin")
        if isinstance(bins, str):
            found.append(bins)
        elif isinstance(bins, dict):
            found += [v for v in bins.values() if isinstance(v, str)]
        stack: list[object] = [document.get("exports")]
        while stack:
            part = stack.pop()
            if isinstance(part, str):
                found.append(part)
            elif isinstance(part, dict):
                stack += list(part.values())
            elif isinstance(part, list):
                stack += part
        scripts = document.get("scripts")
        if isinstance(scripts, dict):
            for name in JsRunning.LIFECYCLE:
                command = scripts.get(name)
                if isinstance(command, str):
                    found += JsRunning.SCRIPT_FILE.findall(command)
        return found

    @staticmethod
    def resolve(base: str, name: str, known: set[str]) -> str | None:
        """The unit a name refers to from `base` (a folder), with the extensions node tries."""
        target = (
            posixpath.normpath(posixpath.join(base, name)) if base else posixpath.normpath(name)
        )
        for candidate in (
            target,
            *(target + ext for ext in SUFFIXES),
            *(f"{target}/index{ext}" for ext in SUFFIXES),
        ):
            if candidate in known and candidate.endswith(SUFFIXES):
                return candidate
        return None

    @staticmethod
    def of(units: list[Any]) -> set[str]:
        """The paths of the units that run, by what each package.json among them names, and what those files require."""
        texts = {u.path: u for u in units if not u.content.is_binary}
        known = set(texts)
        running: set[str] = set()
        for path, unit in texts.items():
            if posixpath.basename(path) != "package.json":
                continue
            try:
                document = json.loads(unit.content.text)
            except (ValueError, RecursionError, MemoryError):
                continue  # a manifest no reader takes to its end names nothing here (the manifest reader reports it)
            base = posixpath.dirname(path)
            for name in JsRunning.named(document):
                hit = JsRunning.resolve(base, name.removeprefix("./"), known)
                if hit is not None:
                    running.add(hit)
        queue = sorted(running)
        while queue and len(running) < JsRunning.MAX_FILES:
            path = queue.pop()
            for name in JsRunning.RELATIVE.findall(texts[path].content.text):
                hit = JsRunning.resolve(posixpath.dirname(path), name, known)
                if hit is not None and hit not in running:
                    running.add(hit)
                    queue.append(hit)
        return running


__all__ = ["SUFFIXES", "JsRunning", "JsUnparsed"]
