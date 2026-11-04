"""Scanned JSON a supervised worker decoded, served to a scan's parent (item 56 (b)): the parent decodes no
scanned JSON.

The context worker decodes every JSON-shaped unit with `ScannedJson.loads` (its text, its bytes, and its
bytes decoded with replacement: the three forms the parent's steps hand the decoder) and sends each
value back as JSON text it wrote. `ServedJson.loads(data, path)` is `ScannedJson.loads(data)` for
scanned content at `path`: while a scan's parent serves (`activate`), the worker's value for those exact
bytes, depth-checked before it is decoded; anywhere else (a worker, the CLI's own files), the decoder.

A document not held is never decoded here: `DocumentUnavailable` is raised, a `ValueError` as a parse
failure is so every caller treats the file as unreadable, and the path is kept (`missing`) for the
engine to report as a blocking gap.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import re
from collections.abc import Iterator
from typing import Any, ClassVar

DOCUMENT_DEPTH = 512
"""The deepest a document crosses as JSON text. Past it (a manifest nested twenty thousand deep, which
`ScannedJson` reads), it crosses as a flat token list (`flatten`) the parent rebuilds without recursion."""


class DocumentUnavailable(ValueError):
    """A manifest or JSON document the context worker did not return."""


class _Served:
    """One scan's store. Per scan, never per process: two scans in one process (a library user's
    threads, the MCP server, the cloud runner) each serve their own (outer-layer review of item 56)."""

    __slots__ = ("active", "held", "missing")

    def __init__(self) -> None:
        self.active = False
        self.held: dict[str, tuple[str | list[Any] | None, str]] = {}
        """sha256 of the input → (the worker's JSON text, or None, and the error type it raised)."""
        self.missing: dict[str, str] = {}
        """Paths asked for and not held, with what was asked."""


class ServedJson:
    """The parent's store of the scanned JSON the context worker decoded, active for one scan."""

    _current: ClassVar[contextvars.ContextVar[_Served | None]] = contextvars.ContextVar(
        "cordon_served_json", default=None
    )

    @staticmethod
    def _scan() -> _Served:
        store = ServedJson._current.get()
        if store is None:
            store = _Served()
            ServedJson._current.set(store)
        return store

    @staticmethod
    def key(data: str | bytes | bytearray) -> str:
        raw = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else bytes(data)
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def depth(text: str) -> int:
        """The deepest nesting of `[` and `{` outside JSON strings, in one linear pass: checked before
        a worker's answer is decoded, since CPython's decoder recurses per level. Only quotes and
        brackets are visited (`_TOKEN`), and a string is skipped by `str.find`: the character-by-
        character walk was 1.9 s of a warm 20,000-file scan's 24.6 s (4 Nov)."""
        deepest = level = position = 0
        while match := ServedJson._TOKEN.search(text, position):
            char, position = match.group(), match.end()
            if char == '"':
                position = ServedJson._string_end(text, position)
                if position < 0:
                    break  # an unterminated string: nothing after it is structure
            elif char in "[{":
                level += 1
                deepest = max(deepest, level)
            else:
                level -= 1
        return deepest

    _TOKEN: ClassVar[re.Pattern[str]] = re.compile(r'["\[\]{}]')

    @staticmethod
    def deeper_than(text: str, limit: int) -> bool:
        """Whether `text` nests `[` and `{` deeper than `limit` outside JSON strings. The same
        answer as `depth(text) > limit`, but a string is skipped in one regex step and the walk stops
        at the first level past `limit`, so a 256 MB document costs what its quotes and brackets
        cost. Linear: each search starts past the last, and a string's end is found by `str.find`.

        The bound is ours, not the decoder's: CPython 3.14 decodes nesting that 3.11 to 3.13 refuse
        with RecursionError, so a limit left to the decoder gave one file two outcomes (4 Nov)."""
        level = position = 0
        while match := ServedJson._TOKEN.search(text, position):
            char, position = match.group(), match.end()
            if char == '"':
                position = ServedJson._string_end(text, position)
                if position < 0:
                    return False  # an unterminated string: nothing after it is structure
            elif char in "[{":
                level += 1
                if level > limit:
                    return True
            else:
                level -= 1
        return False

    @staticmethod
    def _string_end(text: str, start: int) -> int:
        """Where the JSON string opened before `start` ends (just past its quote), or -1 if it
        never does: a quote ends it unless an odd run of backslashes precedes it."""
        while (quote := text.find('"', start)) >= 0:
            slashes = quote - 1
            while slashes >= start and text[slashes] == "\\":
                slashes -= 1
            if (quote - 1 - slashes) % 2 == 0:
                return quote + 1
            start = quote + 1
        return -1

    @staticmethod
    def hold(documents: Any, known: set[str]) -> str:
        """Why the worker's documents are refused, or "" when each has its declared shape and is held."""
        held: dict[str, tuple[str | list[Any] | None, str]] = {}
        for entry in documents if isinstance(documents, list) else [None]:
            if not (
                isinstance(entry, list)
                and len(entry) == 4
                and isinstance(entry[0], str)
                and len(entry[0]) == 64
                and entry[1] in known
                and (entry[2] is None or isinstance(entry[2], (str, list)))
                and isinstance(entry[3], str)
                and len(entry[3]) <= 128
            ):
                return "a document entry of the wrong shape"
            held[entry[0]] = (entry[2], entry[3])
        store = ServedJson._scan()
        store.held.clear()
        store.held.update(held)
        return ""

    @staticmethod
    def activate() -> None:
        store = ServedJson._scan()
        store.missing.clear()
        store.active = True

    @staticmethod
    def end() -> None:
        ServedJson._current.set(None)

    @staticmethod
    def active() -> bool:
        store = ServedJson._current.get()
        return store is not None and store.active

    @staticmethod
    def loads(data: str | bytes | bytearray, path: str) -> Any:
        """`ScannedJson.loads(data)` for scanned content at `path`: in a scan's parent, the worker's
        decoded value (a fresh copy each time), its parse failure as ValueError, or
        DocumentUnavailable; anywhere else, the decoder itself."""
        from cordon_scanner.foundation.formats.scanned_json import ScannedJson

        if not ServedJson.active():
            return ScannedJson.loads(data)
        held = ServedJson._scan().held.get(ServedJson.key(data))
        if held is None:
            return ServedJson.miss(path, "JSON document")
        form, error = held
        if form is None:
            raise DocumentUnavailable(f"not JSON ({error})")
        if isinstance(form, list):
            ok, value = ServedJson.rebuild(form)
            return value if ok else ServedJson.miss(path, "JSON document (malformed tokens)")
        if ServedJson.depth(form) > DOCUMENT_DEPTH:
            return ServedJson.miss(path, f"JSON document nested past {DOCUMENT_DEPTH}")
        return json.loads(form)

    @staticmethod
    def encode(value: Any) -> str | list[Any]:
        """How the worker sends a decoded value: JSON text when it nests within DOCUMENT_DEPTH, else
        the flat tokens (`flatten`), which no decoder ever recurses over."""
        try:
            text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        except (RecursionError, ValueError):
            return ServedJson.flatten(value)
        return text if ServedJson.depth(text) <= DOCUMENT_DEPTH else ServedJson.flatten(value)

    #: A token: ["o"] open an object, ["a"] open an array, ["c"] close, ["k", key], or a value:
    #: ["s", str], ["i", int], ["f", finite float], ["x", "nan" | "inf" | "-inf"], ["t"], ["F"], ["z"].
    CLOSE: ClassVar[list[str]] = ["c"]

    @staticmethod
    def flatten(value: Any) -> list[Any]:
        """A decoded document as flat tokens, in document order, walked with an explicit stack."""
        out: list[Any] = []
        stack: list[tuple[str, Any]] = [("top", iter([value]))]
        while stack:
            kind, items = stack[-1]
            try:
                item = next(items)
            except StopIteration:
                stack.pop()
                if kind != "top":
                    out.append(ServedJson.CLOSE)
                continue
            if kind == "obj":
                out.append(["k", item[0]])
                item = item[1]
            if isinstance(item, dict):
                out.append(["o"])
                stack.append(("obj", iter(item.items())))
            elif isinstance(item, list):
                out.append(["a"])
                stack.append(("arr", iter(item)))
            else:
                out.append(ServedJson._scalar(item))
        return out

    @staticmethod
    def _scalar(value: Any) -> list[Any]:
        import math

        if value is True or value is False:
            return ["t"] if value else ["F"]
        if value is None:
            return ["z"]
        if isinstance(value, str):
            return ["s", value]
        if isinstance(value, int):
            return ["i", value]
        if math.isnan(value):
            return ["x", "nan"]
        if math.isinf(value):
            return ["x", "inf" if value > 0 else "-inf"]
        return ["f", value]

    SCALARS: ClassVar[dict[str, Any]] = {
        "s": lambda a: (isinstance(a, str), a),
        "i": lambda a: (type(a) is int, a),
        "f": lambda a: (type(a) is float, a),
        "x": lambda a: (
            a in ("nan", "inf", "-inf"),
            float(a) if a in ("nan", "inf", "-inf") else 0,
        ),
    }
    FIXED: ClassVar[dict[str, Any]] = {"t": True, "F": False, "z": None}

    @staticmethod
    def rebuild(tokens: list[Any]) -> tuple[bool, Any]:
        """The value `flatten` gave, rebuilt with an explicit stack, every token checked; (False, None)
        for any token out of place."""
        root: list[Any] = []
        stack: list[list[Any]] = []  # [container, the key waiting for its value]

        def place(value: Any) -> bool:
            if not stack:
                if root:
                    return False
                root.append(value)
                return True
            top = stack[-1]
            if isinstance(top[0], dict):
                if top[1] is None:
                    return False
                top[0][top[1]] = value
                top[1] = None
            else:
                top[0].append(value)
            return True

        for token in tokens:
            if not isinstance(token, list) or not token or not isinstance(token[0], str):
                return False, None
            op = token[0]
            if op in ("o", "a") and len(token) == 1:
                new: Any = {} if op == "o" else []
                if not place(new):
                    return False, None
                stack.append([new, None])
            elif op == "c" and len(token) == 1:
                if not stack or stack[-1][1] is not None:
                    return False, None
                stack.pop()
            elif op == "k" and len(token) == 2 and isinstance(token[1], str):
                if not stack or not isinstance(stack[-1][0], dict) or stack[-1][1] is not None:
                    return False, None
                stack[-1][1] = token[1]
            elif op in ServedJson.FIXED and len(token) == 1:
                if not place(ServedJson.FIXED[op]):
                    return False, None
            elif op in ServedJson.SCALARS and len(token) == 2:
                ok, value = ServedJson.SCALARS[op](token[1])
                if not ok or not place(value):
                    return False, None
            else:
                return False, None
        return (len(root) == 1 and not stack), (root[0] if root else None)

    @staticmethod
    @contextlib.contextmanager
    def serving(where: str) -> Iterator[None]:
        """`ScannedJson.loads` served from this store while the block runs, in a scan's parent: the
        verdict's and the intent layer's reads of a package's JSON (item 56 (b)), whose code is the
        verdict features' and stays as it is (`FeatureSchema` hashes it). Outside a serving scan, or
        in a worker, the block reads as before."""
        from cordon_scanner.foundation.formats.scanned_json import ScannedJson

        if not ServedJson.active():
            yield
            return
        token = ScannedJson.SERVE.set(lambda data: ServedJson.loads(data, where))
        try:
            yield
        finally:
            ScannedJson.SERVE.reset(token)

    @staticmethod
    def miss(path: str, what: str) -> Any:
        ServedJson._scan().missing.setdefault(path, what)
        raise DocumentUnavailable(f"the context worker returned no {what} for this file")

    @staticmethod
    def missing() -> dict[str, str]:
        """The paths asked for and not held since the last call, with what was asked."""
        store = ServedJson._scan()
        out = dict(store.missing)
        store.missing.clear()
        return out


__all__ = ["DOCUMENT_DEPTH", "DocumentUnavailable", "ServedJson"]
