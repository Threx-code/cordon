"""`ScannedJson.loads` reads what `json.loads` reads, at any depth, and fails where it fails, as it fails."""

from __future__ import annotations

import json
import math
import random
from typing import Any

import pytest

from cordon_scanner.foundation.formats.jsonc import Jsonc
from cordon_scanner.foundation.formats.scanned_json import JsonTooDeep, ScannedJson, _Iterative


class Documents:
    """JSON documents to read, built from a seed, and an equality that does not recurse."""

    CHARS = ("a", "é", '\\"', "\\\\", "\\n", "\\u00e9", "\\ud83d\\ude00", "\\ud800", "\t", "\x01")
    NUMBERS = (
        "0",
        "-0",
        "1",
        "-12",
        "3.5",
        "1e3",
        "-2.5E-7",
        "1E+2",
        "0.0",
        "12345678901234567890.5",
    )
    SPACES = ("", " ", "\n", "\t", "\r", " \n ")
    #: What a mutation inserts: delimiters, broken literals, a BOM, digits that are not ASCII.
    BREAKS = (",", ":", "]", "}", "[", "{", '"', " ", "x", "01", "-", ".", "e", "\\", "\x00", "tru")
    BREAKS += ("nul", "Na", "-I", "\ufeff", chr(0x661), "1" + chr(0x662))

    @staticmethod
    def nested(depth: int, opener: str = "{") -> str:
        if opener == "{":
            return '{"a":' * depth + "1" + "}" * depth
        return "[" * depth + "]" * depth

    @staticmethod
    def random(seed: int) -> str:
        rnd = random.Random(seed)  # noqa: S311 - a seeded generator for test documents

        def value(depth: int) -> object:
            kind = rnd.randint(0, 6 if depth < 6 else 3)
            if kind == 0:
                return rnd.randint(-(10**6), 10**6)
            if kind == 1:
                return rnd.choice(["", "x", "[{]}", '"', "\\", "é", chr(0x2028)])
            if kind == 2:
                return rnd.choice([True, False, None, 1.5])
            if kind == 3:
                return "".join(rnd.choice('ab[]{}"\\') for _ in range(rnd.randint(0, 6)))
            if kind in (4, 5):
                return [value(depth + 1) for _ in range(rnd.randint(0, 4))]
            return {f"k{i}": value(depth + 1) for i in range(rnd.randint(0, 4))}

        return json.dumps(value(0))

    @staticmethod
    def text(seed: int) -> str | bytes:
        """A document as written by hand: spacing, duplicate keys, constants -- and, often, broken."""
        rnd = random.Random(seed)  # noqa: S311 - a seeded generator for test documents

        def space() -> str:
            return rnd.choice(Documents.SPACES) if rnd.random() < 0.4 else ""

        def value(depth: int) -> str:
            kind = rnd.random()
            if depth <= 0 or kind < 0.2:
                return rnd.choice(
                    [
                        '"'
                        + "".join(rnd.choice(Documents.CHARS) for _ in range(rnd.randint(0, 4)))
                        + '"',
                        rnd.choice(Documents.NUMBERS),
                        str(rnd.randint(-(10**30), 10**30)),
                        rnd.choice(["true", "false", "null", "NaN", "Infinity", "-Infinity"]),
                    ]
                )
            if kind < 0.6:
                items = [space() + value(depth - 1) + space() for _ in range(rnd.randint(0, 3))]
                return "[" + space() + ",".join(items) + "]"
            keys = [f'"k{rnd.randint(0, 3)}"' for _ in range(rnd.randint(0, 3))]
            pairs = [space() + k + space() + ":" + space() + value(depth - 1) for k in keys]
            return "{" + space() + ",".join(pairs) + "}"

        text = space() + value(rnd.randint(0, 6)) + space()
        if rnd.random() < 0.5:
            for _ in range(rnd.randint(1, 3)):
                at = rnd.randint(0, len(text))
                text = text[:at] + rnd.choice(Documents.BREAKS) + text[at + rnd.randint(0, 1) :]
        if rnd.random() < 0.25:
            return text.encode(
                rnd.choice(["utf-8", "utf-16", "utf-32", "utf-8-sig"]), "surrogatepass"
            )
        return text

    @staticmethod
    def outcome(loads: Any, text: str | bytes) -> tuple[Any, ...]:
        try:
            return ("value", loads(text))
        except json.JSONDecodeError as error:
            return ("JSONDecodeError", error.msg, error.pos, error.lineno, error.colno)
        except (ValueError, TypeError) as error:
            return (type(error).__name__, str(error))

    @staticmethod
    def same(left: object, right: object) -> bool:
        """Equal values of equal types, NaN equal to NaN, -0.0 apart from 0.0, keys in order."""
        work = [(left, right)]
        while work:
            a, b = work.pop()
            if type(a) is not type(b):
                return False
            if isinstance(a, float) and isinstance(b, float):
                if not ((math.isnan(a) and math.isnan(b)) or (a == b and str(a) == str(b))):
                    return False
            elif isinstance(a, list) and isinstance(b, list):
                if len(a) != len(b):
                    return False
                work.extend(zip(a, b, strict=True))
            elif isinstance(a, dict) and isinstance(b, dict):
                if list(a) != list(b):
                    return False
                work.extend((a[k], b[k]) for k in a)
            elif a != b:
                return False
        return True

    @staticmethod
    def depth_of(value: object) -> int:
        """How deeply a decoded value nests, counted without recursion."""
        deepest, work = 0, [(value, 0)]
        while work:
            item, level = work.pop()
            if isinstance(item, (list, dict)):
                deepest = max(deepest, level + 1)
                work.extend(
                    (v, level + 1) for v in (item.values() if isinstance(item, dict) else item)
                )
        return deepest


class TestScannedJson:
    def test_it_reads_what_json_reads(self) -> None:
        for seed in range(2000):
            text = Documents.random(seed)
            assert ScannedJson.loads(text) == json.loads(text)
            assert ScannedJson.loads(text.encode()) == json.loads(text.encode())

    def test_the_stack_decoder_gives_what_json_gives(self) -> None:
        # Valid and broken alike: the same value and types, or the same error at the same position.
        for seed in range(5000):
            text = Documents.text(seed)
            expected = Documents.outcome(json.loads, text)
            got = Documents.outcome(_Iterative.loads, text)
            assert got[0] == expected[0], (text, expected, got)
            if expected[0] == "value":
                assert Documents.same(got[1], expected[1]), text
            else:
                assert got == expected, text

    @pytest.mark.parametrize(
        "text",
        [
            "1" * 5000,  # past the interpreter's integer-string limit: the same ValueError
            "1e999",
            "-1e999",
            '"\\ud800"',
            '"\\udc00\\ud800"',
            b"",
            b"\xef\xbb\xbf[1]",
            "\ufeff[1]",
            "[1]".encode("utf-16"),
            '{"a":1,"a":2}',
            "[NaN,Infinity,-Infinity]",
            "[-NaN]",
            "[1,2",
            '{"a"',
            "[1,]",
            '{"a":1,}',
            chr(0x661),
        ],
    )
    def test_the_stack_decoder_on_the_edges(self, text: str | bytes) -> None:
        expected = Documents.outcome(json.loads, text)
        got = Documents.outcome(_Iterative.loads, text)
        assert got[0] == expected[0]
        assert Documents.same(got[1], expected[1]) if got[0] == "value" else got == expected

    @pytest.mark.parametrize("depth", [10_001, 20_000, 100_000])
    def test_it_reads_a_document_nested_to_any_depth(self, depth: int) -> None:
        for opener in ("{", "["):
            value = ScannedJson.loads(Documents.nested(depth, opener))
            assert Documents.depth_of(value) == depth
            assert (
                Documents.depth_of(ScannedJson.loads(Documents.nested(depth, opener).encode()))
                == depth
            )

    def test_a_deep_document_that_is_not_json_fails_as_json_would_say(self) -> None:
        text = "[" * 20_000
        with pytest.raises(json.JSONDecodeError) as error:
            ScannedJson.loads(text)
        assert (error.value.msg, error.value.pos) == ("Expecting value", 20_000)

    def test_both_decoders_agree_where_json_still_reads(self) -> None:
        for depth in (100, 1_000, 5_000):
            for opener in ("{", "["):
                text = Documents.nested(depth, opener)
                assert Documents.same(_Iterative.loads(text), json.loads(text))

    def test_brackets_inside_strings_do_not_count(self) -> None:
        text = json.dumps({"a": "[" * 10_000 + "{" * 10_000, "b": ['"\\["' * 5_000]})
        assert ScannedJson.loads(text) == json.loads(text)

    def test_jsonc_reads_any_depth_too(self) -> None:
        assert Documents.depth_of(Jsonc.loads(Documents.nested(20_000))) == 20_000

    def test_the_guard_is_not_taken_for_malformed_json(self) -> None:
        # Should the stack decoder ever fail on depth, a reader that skips malformed JSON in silence
        # must not skip the file: the guard is a RecursionError, as such a document always raised.
        assert issubclass(JsonTooDeep, RecursionError)
        assert not issubclass(JsonTooDeep, ValueError)
