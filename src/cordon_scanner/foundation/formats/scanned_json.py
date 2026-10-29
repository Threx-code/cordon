"""Read JSON a scanned package wrote, at any depth.

Python's decoder recurses once per level of nesting, so a document nested past the interpreter's
recursion limit -- a `package.json` whose `config` holds twenty thousand `{"a":` -- raised
`RecursionError` wherever it was read. Where that was outside a detector's own isolation (the verdict's
package features read every `package.json`), it ended the whole scan as "internal error", exit 2, with
no report: one manifest an attacker writes made a CI gate see a scanner failure instead of a hostile
package (review 98, 27-PERFORMANCE, 7). Where it was inside, the file went unread and the scan
incomplete, which a parser's test suite (JSONTestSuite's `n_structure_100000_opening_arrays.json`)
was enough to cause.

`ScannedJson.loads` reads every depth. A document is read by `json.loads` itself, unchanged; one the C
decoder refuses as too deep (measured: a 9,937-deep document is read, 10,000 refused, in a whole scan)
is read again by `_Iterative`, the same grammar with an explicit stack in place of recursion. It gives
what `json.loads` gives: the same values and types, and for a document that is not JSON the same
`JSONDecodeError` at the same position. The decoder's own refusal is the signal, so an ordinary
document -- a lockfile of a hundred thousand brackets as much as a manifest -- costs exactly what it
did; the file-size limit the caller already applies bounds memory, and time is linear in the document.

`JsonTooDeep` is the guard should that path ever fail on depth: a `RecursionError`, what such a document
always raised, so every reader handles it as it did -- a detector's isolation records the detector as
failed and the scan incomplete. It is deliberately not a `ValueError`, which many readers take to mean
"not my file" and skip in silence.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from json.decoder import JSONDecodeError
from typing import Any, ClassVar

#: `json.decoder`'s own string scanner (the C one where it is built), so the stack decoder reads
#: strings with exactly what `json.loads` reads them with; and its whitespace.
scanstring: Callable[[str, int, bool], tuple[str, int]] = vars(json.decoder)["scanstring"]
WHITESPACE = re.compile(r"[ \t\n\r]*", re.VERBOSE | re.MULTILINE | re.DOTALL)
WHITESPACE_STR = " \t\n\r"


class JsonTooDeep(RecursionError):
    """A JSON document no decoder here could read for its depth."""


class ScannedJson:
    """JSON read from scanned content. Stateless; call the static methods."""

    @staticmethod
    def loads(text: str | bytes | bytearray, **options: Any) -> Any:
        """`json.loads(text, **options)`, at any depth."""
        try:
            return json.loads(text, **options)
        except RecursionError:
            if options:
                # No reader passes decoder options; the stack decoder reads the default grammar only.
                raise JsonTooDeep("JSON nested too deeply to decode") from None
        try:
            return _Iterative.loads(text)
        except RecursionError as error:
            raise JsonTooDeep("JSON nested too deeply to decode") from error


class _Iterative:
    """`json.loads` with an explicit stack: CPython's `JSONObject`, `JSONArray` and `scan_once`, whose
    positions the C decoder keeps, unrolled into a loop. Each comment names the step it mirrors."""

    #: The C scanner's number: ASCII digits only (`json.scanner.NUMBER_RE`'s `\\d` also takes others).
    NUMBER = re.compile(r"(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?")
    CONSTANTS: ClassVar[dict[str, float]] = {
        "NaN": float("nan"),
        "Infinity": float("inf"),
        "-Infinity": float("-inf"),
    }

    @staticmethod
    def loads(text: str | bytes | bytearray) -> Any:
        """`json.loads(text)`: its input handling, then `JSONDecoder.decode`."""
        if isinstance(text, str):
            if text.startswith("\ufeff"):
                raise JSONDecodeError("Unexpected UTF-8 BOM (decode using utf-8-sig)", text, 0)
            s = text
        elif isinstance(text, (bytes, bytearray)):
            s = text.decode(json.detect_encoding(text), "surrogatepass")
        else:
            raise TypeError(
                f"the JSON object must be str, bytes or bytearray, not {text.__class__.__name__}"
            )
        value, end = _Iterative.decode(s, _Iterative.space(s, 0))
        end = _Iterative.space(s, end)
        if end != len(s):
            raise JSONDecodeError("Extra data", s, end)
        return value

    @staticmethod
    def space(s: str, end: int) -> int:
        """`_w(s, end).end()`: past the whitespace at `end` (the pattern matches even none)."""
        match = WHITESPACE.match(s, end)
        return match.end() if match is not None else end

    @staticmethod
    def _space_after(s: str, end: int) -> int:
        """The two-character fast path both containers take after a delimiter."""
        try:
            if s[end] in WHITESPACE_STR:
                end += 1
                if s[end] in WHITESPACE_STR:
                    end = _Iterative.space(s, end + 1)
        except IndexError:
            pass
        return end

    @staticmethod
    def _object_key(s: str, end: int) -> tuple[str, int]:
        """`JSONObject`: a key whose opening quote is just before `end`, its `:`, the space after it."""
        key, end = scanstring(s, end, True)
        if s[end : end + 1] != ":":
            end = _Iterative.space(s, end)
            if s[end : end + 1] != ":":
                raise JSONDecodeError("Expecting ':' delimiter", s, end)
        return key, _Iterative._space_after(s, end + 1)

    @staticmethod
    def _scalar(s: str, idx: int) -> tuple[Any, int]:
        """`scan_once` for anything but an array or object: `Expecting value` where it finds none."""
        if s[idx : idx + 1] == '"':
            return scanstring(s, idx + 1, True)
        for word, constant in (("null", None), ("true", True), ("false", False)):
            if s.startswith(word, idx):
                return constant, idx + len(word)
        number = _Iterative.NUMBER.match(s, idx)
        if number is not None:
            integer, frac, exp = number.groups()
            if frac or exp:
                return float(integer + (frac or "") + (exp or "")), number.end()
            return int(integer), number.end()
        for word, value in _Iterative.CONSTANTS.items():
            if s.startswith(word, idx):
                return value, idx + len(word)
        raise JSONDecodeError("Expecting value", s, idx)

    @staticmethod
    def _open(s: str, idx: int, stack: list[list[Any]]) -> tuple[bool, Any, int]:
        """A value at `idx`: (True, value, end) for one complete here, or (False, None, where the
        next value starts) for a container opened onto `stack` -- [values] or [pairs, key]."""
        nextchar = s[idx : idx + 1]
        if nextchar == "[":
            # JSONArray: the look-ahead for an empty array.
            end = idx + 1
            nextchar = s[end : end + 1]
            if nextchar and nextchar in WHITESPACE_STR:
                end = _Iterative.space(s, end + 1)
                nextchar = s[end : end + 1]
            if nextchar == "]":
                return True, [], end + 1
            stack.append([[]])
            return False, None, end
        if nextchar == "{":
            # JSONObject: the look-ahead for an empty object, then the first key.
            end = idx + 1
            nextchar = s[end : end + 1]
            if nextchar != '"':
                if nextchar and nextchar in WHITESPACE_STR:
                    end = _Iterative.space(s, end)
                    nextchar = s[end : end + 1]
                if nextchar == "}":
                    return True, {}, end + 1
                if nextchar != '"':
                    raise JSONDecodeError(
                        "Expecting property name enclosed in double quotes", s, end
                    )
            key, start = _Iterative._object_key(s, end + 1)
            stack.append([[], key])
            return False, None, start
        value, end = _Iterative._scalar(s, idx)
        return True, value, end

    @staticmethod
    def _close(s: str, value: Any, end: int, stack: list[list[Any]]) -> tuple[bool, Any, int]:
        """A value that ended at `end`, taken into the container open on top of `stack`: (True,
        the container, end) when that closes it, or (False, None, where the next value starts)."""
        frame = stack[-1]
        if len(frame) == 1:
            # JSONArray: after a value.
            frame[0].append(value)
            nextchar = s[end : end + 1]
            if nextchar and nextchar in WHITESPACE_STR:
                end = _Iterative.space(s, end + 1)
                nextchar = s[end : end + 1]
            end += 1
            if nextchar == "]":
                return True, stack.pop()[0], end
            if nextchar != ",":
                raise JSONDecodeError("Expecting ',' delimiter", s, end - 1)
            return False, None, _Iterative._space_after(s, end)
        # JSONObject: after a value.
        frame[0].append((frame[1], value))
        try:
            nextchar = s[end]
            if nextchar in WHITESPACE_STR:
                end = _Iterative.space(s, end + 1)
                nextchar = s[end]
        except IndexError:
            nextchar = ""
        end += 1
        if nextchar == "}":
            return True, dict(stack.pop()[0]), end
        if nextchar != ",":
            raise JSONDecodeError("Expecting ',' delimiter", s, end - 1)
        end = _Iterative.space(s, end)
        nextchar = s[end : end + 1]
        end += 1
        if nextchar != '"':
            raise JSONDecodeError("Expecting property name enclosed in double quotes", s, end - 1)
        frame[1], start = _Iterative._object_key(s, end)
        return False, None, start

    @staticmethod
    def decode(s: str, idx: int) -> tuple[Any, int]:
        """`scan_once(s, idx)`: the value at `idx` and the offset after it."""
        stack: list[list[Any]] = []
        while True:
            done, value, end = _Iterative._open(s, idx, stack)
            if not done:
                idx = end
                continue
            # A value ended: it closes into the containers above it, as many as close here.
            while stack:
                done, value, end = _Iterative._close(s, value, end, stack)
                if not done:
                    break
            if not stack and done:
                return value, end
            idx = end
