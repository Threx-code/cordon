"""Per-file facts from a worker to the parent (item 56, phase (a)): the result channel's fifth element.

The parent never parses scanned content, so what it needs to know across files (what a hook-run file
imports, what a script requires) is read in the worker and sent back as facts. The channel is where a
worker's output becomes the parent's input, and the worker is where hostile content lives, so a fact
is held to three rules on the way in (cordon-47, 1 Nov):

```
  worker: WorkerFacts.add(kind, value)  per unit  ──►  json.dumps  (plain data, or nothing crosses)
                                                            │
  parent: Facts.accept(text) ◄──────────────────────────────┘
            ├─ json.loads only: str, int, float, bool, None, lists and dicts, never an object
            ├─ bounded: FILE_COUNT and FILE_BYTES per file, SCAN_BYTES per scan
            └─ each kind against its declared shape (KINDS); an unknown kind or a wrong type refuses
               the file's facts, a gap at that file, never a partial set
```
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

FILE_COUNT = 20_000
"""The most facts one file may send back."""
FILE_BYTES = 2 << 20
"""The most bytes one file's encoded facts may take."""
SCAN_BYTES = 64 << 20
"""The most bytes all files' facts may take in one scan."""
MAX_DEPTH = 4
"""The deepest a facts payload nests: a mapping of kinds, a list of facts, a fact's fields (3), and one
level of slack. Each declared shape is at most 3 deep."""
OVERSIZED = '{"__oversized__":[]}'
"""What a worker sends instead of a set past its bounds: refused by the parent as an undeclared kind."""
UNENCODABLE = '{"__unencodable__":[]}'
"""What a worker sends for a set holding a value JSON can't encode (not plain data)."""


class Shapes:
    """Each fact kind's declared shape, checked field by field."""

    @staticmethod
    def python_import(value: Any) -> bool:
        """(module, level, line, scope): a dotted name, a relative level, a line, and module,
        function or class (note 56's review: the closure's scope and line reach read these)."""
        return (
            isinstance(value, list)
            and len(value) == 4
            and isinstance(value[0], str)
            and len(value[0]) <= 512
            and type(value[1]) is int
            and 0 <= value[1] <= 64
            and type(value[2]) is int
            and value[2] >= 0
            and value[3] in ("module", "function", "class")
        )

    @staticmethod
    def dotted_path(value: Any) -> bool:
        return isinstance(value, str) and 0 < len(value) <= 512

    @staticmethod
    def module_name(value: Any) -> bool:
        """A dependency name the verdict asked about (scoped or not)."""
        return isinstance(value, str) and 0 < len(value) <= 214

    @staticmethod
    def ability(value: Any) -> bool:
        from cordon_scanner.decide.verdict_features import VerdictFeatures

        return isinstance(value, str) and value in VerdictFeatures.ABILITY

    @staticmethod
    def js_require(value: Any) -> bool:
        """A require's resolved literal path, or "dynamic" (an evasion signal, never an edge)."""
        return isinstance(value, str) and 0 < len(value) <= 4096


class Facts:
    """The parent's side of the channel: what it accepts from a worker, and nothing else."""

    KINDS: ClassVar[dict[str, Any]] = {
        "python.import": Shapes.python_import,
        "python.dotted_path": Shapes.dotted_path,
        "js.require": Shapes.js_require,
        "verdict.modules": Shapes.module_name,
        "verdict.abilities": Shapes.ability,
    }

    @staticmethod
    def depth(text: str) -> int:
        """The deepest nesting of `[` and `{` outside JSON strings, in one linear pass."""
        deepest = level = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                level += 1
                deepest = max(deepest, level)
            elif char in "]}":
                level -= 1
        return deepest

    @staticmethod
    def accept(text: str, spent: int) -> tuple[dict[str, list[Any]] | None, str]:
        """A file's facts, decoded and checked, or None with why they were refused. `spent` is the
        bytes earlier files' facts took in this scan. Plain data only: `json.loads` builds nothing
        but strings, numbers, booleans, None, lists and dicts."""
        if not text:
            return {}, ""
        if len(text) > FILE_BYTES:
            return None, f"{len(text)} bytes of facts, past the {FILE_BYTES} a file may send"
        if spent + len(text) > SCAN_BYTES:
            return None, f"the scan's facts passed {SCAN_BYTES} bytes"
        if Facts.depth(text) > MAX_DEPTH:
            # Before decoding: CPython's decoder recurses per level and raises RecursionError on a
            # deep payload a fraction of FILE_BYTES long (cordon-47's review).
            return None, "facts nested past the declared shapes' depth"
        try:
            decoded = json.loads(text)
        except (ValueError, RecursionError, MemoryError):
            return None, "facts that are not JSON within the decoder's limits"
        if not isinstance(decoded, dict):
            return None, "facts that are not a mapping of kinds"
        count = 0
        for kind, values in decoded.items():
            check = Facts.KINDS.get(kind)
            if kind == "__oversized__":
                return None, f"more than {FILE_COUNT} facts or {FILE_BYTES} bytes"
            if kind == "__unencodable__":
                return None, "a fact that is not plain data"
            if check is None:
                return None, f"an undeclared fact kind {kind[:80]!r}"
            if not isinstance(values, list):
                return None, f"{kind}'s facts are not a list"
            count += len(values)
            if count > FILE_COUNT:
                return None, f"more than {FILE_COUNT} facts"
            if not all(check(value) for value in values):
                return None, f"a {kind} fact of the wrong shape"
        return decoded, ""


class WorkerFacts:
    """The worker's side: facts gathered while one unit is inspected, encoded for the channel."""

    _current: ClassVar[dict[str, list[Any]] | None] = None
    _count: ClassVar[int] = 0
    _over: ClassVar[bool] = False

    @staticmethod
    def begin() -> None:
        WorkerFacts._current, WorkerFacts._count, WorkerFacts._over = {}, 0, False

    @staticmethod
    def add(kind: str, value: Any) -> None:
        """Record a fact for the unit being inspected; nothing when no unit is (the parent)."""
        if WorkerFacts._current is None or WorkerFacts._over:
            return
        WorkerFacts._count += 1
        if WorkerFacts._count > FILE_COUNT:
            # Bounded here, in the worker, so an inflated set never crosses to the parent at all.
            WorkerFacts._over, WorkerFacts._current = True, {}
            return
        WorkerFacts._current.setdefault(kind, []).append(value)

    @staticmethod
    def end() -> str:
        """The unit's facts as JSON, and the sink closed. A value JSON can't encode is dropped
        with the whole set, so only plain data ever crosses."""
        gathered, over = WorkerFacts._current, WorkerFacts._over
        WorkerFacts._current, WorkerFacts._over = None, False
        if over:
            return OVERSIZED
        if not gathered:
            return ""
        try:
            text = json.dumps(gathered, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            return UNENCODABLE
        return OVERSIZED if len(text) > FILE_BYTES else text


__all__ = ["FILE_BYTES", "FILE_COUNT", "SCAN_BYTES", "Facts", "Shapes", "WorkerFacts"]
