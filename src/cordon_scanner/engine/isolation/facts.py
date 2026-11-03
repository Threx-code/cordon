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
    def capability(value: Any) -> bool:
        from cordon_scanner.foundation.capabilities import Capability

        return isinstance(value, str) and value in {c.value for c in Capability}

    @staticmethod
    def marker(value: Any) -> bool:
        """A flag fact (`cap.error`, `cap.download`): present or absent, its value fixed."""
        return value in ("raised", "runs")

    @staticmethod
    def intent_effect(value: Any) -> bool:
        """[capability, deferred]: an effect the intent layer groups, and whether it is deferred."""
        from cordon_scanner.decide.intent import IntentFacts

        return (
            isinstance(value, list)
            and len(value) == 2
            and isinstance(value[0], str)
            and value[0] in IntentFacts.EFFECT_GROUP
            and type(value[1]) is bool
        )

    @staticmethod
    def intent_fact(value: Any) -> bool:
        """A concealment or gate fact, as the intent layer names them."""
        from cordon_scanner.decide.intent import IntentFacts

        return (
            isinstance(value, str) and len(value) <= 128 and IntentFacts.classify(value) is not None
        )

    @staticmethod
    def reached_flow(value: Any) -> bool:
        """A reached-flow fact without its place: `can_<name>` or `flow_<source>_<sink>_<dest>`."""
        import re

        return (
            isinstance(value, str)
            and re.fullmatch(r"(?:can|flow)_[a-z0-9_]{1,200}", value) is not None
        )

    @staticmethod
    def js_require(value: Any) -> bool:
        """A require's resolved literal path, or "dynamic" (an evasion signal, never an edge)."""
        return isinstance(value, str) and 0 < len(value) <= 4096


class JsShapes:
    """The cross-file summaries' shapes (item 60, `flow/summaries.py`): names and module paths bounded
    in length, labels from the declared vocabulary (a source kind, P<0..63>, C<k>), a destination its
    class, never a host."""

    NAME: ClassVar[int] = 256
    LABEL: ClassVar[str] = r"P(?:[0-9]|[1-5][0-9]|6[0-3])|C[0-9]{1,9}"
    DESTINATIONS: ClassVar[frozenset[str]] = frozenset({"drop", "ip", "fixed", "unknown"})

    @staticmethod
    def _name(value: Any, most: int = NAME) -> bool:
        return isinstance(value, str) and 0 < len(value) <= most

    @staticmethod
    def _int(value: Any, lowest: int = 0) -> bool:
        return type(value) is int and lowest <= value < 1 << 31

    @staticmethod
    def label(value: Any) -> bool:
        import re

        from cordon_scanner.analysis.javascript.flow.vocabulary import SOURCES

        return isinstance(value, str) and (
            value in SOURCES or re.fullmatch(JsShapes.LABEL, value) is not None
        )

    @staticmethod
    def sink(value: Any) -> bool:
        return isinstance(value, str) and 0 < len(value) <= 32 and value.isidentifier()

    @staticmethod
    def export(value: Any) -> bool:
        """[name, param_count]."""
        return (
            isinstance(value, list)
            and len(value) == 2
            and JsShapes._name(value[0])
            and JsShapes._int(value[1])
            and value[1] <= 1024
        )

    @staticmethod
    def summary(value: Any) -> bool:
        """[name, from, to]: from a label, to "return" or "sink:<kind>:<destination class>"."""
        if not (isinstance(value, list) and len(value) == 3 and JsShapes._name(value[0])):
            return False
        if not JsShapes.label(value[1]) or not isinstance(value[2], str):
            return False
        if value[2] == "return":
            return True
        parts = value[2].split(":")
        return (
            len(parts) == 3
            and parts[0] == "sink"
            and JsShapes.sink(parts[1])
            and parts[2] in JsShapes.DESTINATIONS
        )

    @staticmethod
    def callout(value: Any) -> bool:
        """[module, name, arg_index, labels, line, caller, "C<k>"]."""
        return (
            isinstance(value, list)
            and len(value) == 7
            and JsShapes._name(value[0], 4096)
            and JsShapes._name(value[1])
            and JsShapes._int(value[2], -1)
            and value[2] < 8
            and isinstance(value[3], list)
            and len(value[3]) <= 16
            and all(JsShapes.label(x) for x in value[3])
            and JsShapes._int(value[4])
            and isinstance(value[5], str)
            and len(value[5]) <= JsShapes.NAME
            and JsShapes.label(value[6])
            and value[6].startswith("C")
        )

    @staticmethod
    def callsink(value: Any) -> bool:
        """["C<k>", sink, destination class, line]."""
        return (
            isinstance(value, list)
            and len(value) == 4
            and JsShapes.label(value[0])
            and value[0].startswith("C")
            and JsShapes.sink(value[1])
            and value[2] in JsShapes.DESTINATIONS
            and JsShapes._int(value[3])
        )

    @staticmethod
    def reexport(value: Any) -> bool:
        """[module]: a local path the file hands on whole."""
        return isinstance(value, list) and len(value) == 1 and JsShapes._name(value[0], 4096)


class Facts:
    """The parent's side of the channel: what it accepts from a worker, and nothing else."""

    KINDS: ClassVar[dict[str, Any]] = {
        "python.import": Shapes.python_import,
        "python.dotted_path": Shapes.dotted_path,
        "js.require": Shapes.js_require,
        "verdict.modules": Shapes.module_name,
        "verdict.abilities": Shapes.ability,
        "cap.label": Shapes.capability,
        "cap.error": Shapes.marker,
        "cap.download": Shapes.marker,
        "intent.effect": Shapes.intent_effect,
        "intent.fact": Shapes.intent_fact,
        "reached.flow": Shapes.reached_flow,
        "js.export": JsShapes.export,
        "js.summary": JsShapes.summary,
        "js.callout": JsShapes.callout,
        "js.callsink": JsShapes.callsink,
        "js.reexport": JsShapes.reexport,
    }

    @staticmethod
    def depth(text: str) -> int:
        """The deepest nesting of `[` and `{` outside JSON strings (`ServedJson.depth`)."""
        from cordon_scanner.foundation.formats.served_json import ServedJson

        return ServedJson.depth(text)

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


__all__ = ["FILE_BYTES", "FILE_COUNT", "SCAN_BYTES", "Facts", "JsShapes", "Shapes", "WorkerFacts"]
