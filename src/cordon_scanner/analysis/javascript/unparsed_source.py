"""JavaScript that runs and that no reader can take to its end: a content gap, or said (BP-15-19).

The Python side decides this for every file that runs when a package is installed or imported
(`analysis/python/unparsed_source.py`): a file that does not parse is a gap when it names anything that
could run its pieces, and `SOURCE.BROKEN` (said, not a gap) when it names nothing. The JavaScript readers
take tokens, not a syntax tree, so a file whose brackets do not close was read as far as it went and
passed without a word: an entry of 200,000 open parentheses was a complete scan.

```
  running files = import entries (main, exports, bin) + the install hooks' files
        │
        ▼  its brackets do not close (a close of another kind, a close with nothing open, an open at the end)
  an act token anywhere in the file (eval, Function, require, import, child_process, a network, a decoder) ─► SOURCE.UNPARSED, a gap,
        │ no                                                                                                  and the running verdict
        ▼
  SOURCE.BROKEN, said: Node refuses the file when it is loaded, so nothing in it runs
```

A file the reader only has a prefix of (it was cut at the size cap) is not decided here: a prefix does not close, and a cut file is a recorded
fact of its own (`OPERATIONAL.FILE.TRUNCATED`). A file nothing runs -- a test, a template, an unused module -- is not reported.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Final

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

    @staticmethod
    def runs_as_source(path: str, running: set[str]) -> bool:
        return path in running and path.endswith(SUFFIXES)

    @staticmethod
    def closes(text: str) -> bool | None:
        """Whether every bracket closes with its own kind. None when the reader's own bound was reached (no verdict: a gap)."""
        try:
            tokens = JsEval.tokens(text, templates=True)
        except (RecursionError, MemoryError, ValueError):
            return None
        stack: list[str] = []
        for token in tokens:
            if token.kind != "punct":
                continue
            if token.value in _OPEN:
                stack.append(_OPEN[token.value])
            elif token.value in _CLOSE and (not stack or stack.pop() != token.value):
                return False
        return not stack

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


__all__ = ["SUFFIXES", "JsUnparsed"]
