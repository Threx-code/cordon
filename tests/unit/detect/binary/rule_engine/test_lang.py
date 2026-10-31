"""cordon-rule's language (`detect/binary/rule_engine/lang`), held to the reference suite.

`data/rule_reference/reference-suite-rules.json` holds the reference suite's cases whose rule and
data are literals (where they come from: that directory's README): each rule matches, does not, or
does not compile. Each is run here with the external variables and the `tests` module the suite's
harness provides, and must come out as the suite says.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.modules.values import (
    Call,
    Data,
    Keyed,
    Module,
    Record,
    Scalar,
    Seq,
    Sig,
)
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.tokens import Includes
from support import ROOT


class ReferenceSuite:
    """The `tests` module the reference suite's harness loads, and its external variables."""

    EXTERNALS: ClassVar[dict[str, Any]] = {
        "var_zero": 0,
        "var_one": 1,
        "var_true": True,
        "var_false": False,
    }
    CASES: ClassVar[list[dict[str, str]]] = json.loads(
        (
            ROOT / "tests" / "unit" / "data" / "rule_reference" / "reference-suite-rules.json"
        ).read_text(encoding="utf-8")
    )

    INT, FLOAT, TEXT = Scalar.INT, Scalar.FLOAT, Scalar.TEXT
    SCHEMA: ClassVar[Record] = Record(
        {
            "constants": Record({"one": INT, "two": INT, "foo": TEXT, "empty": TEXT}),
            "undefined": Record({"i": INT, "f": FLOAT}),
            "module_data": TEXT,
            "integer_array": Seq(INT),
            "string_array": Seq(TEXT),
            "integer_dict": Keyed(INT),
            "string_dict": Keyed(TEXT),
            "struct_array": Seq(Record({"i": INT, "s": TEXT})),
            "struct_dict": Keyed(Record({"i": INT, "s": TEXT})),
            "empty_struct_dict": Keyed(Record({"unused": INT})),
            "empty_struct_array": Seq(
                Record(
                    {
                        "struct_array": Seq(Record({"unused": TEXT})),
                        "struct_dict": Keyed(Record({"unused": TEXT})),
                    }
                )
            ),
            "match": Call(Sig(("regex", "text"), INT)),
            "isum": Call(Sig(("int", "int"), INT), Sig(("int", "int", "int"), INT)),
            "fsum": Call(Sig(("float", "float"), FLOAT), Sig(("float", "float", "float"), FLOAT)),
            "length": Call(Sig(("text",), INT)),
            "empty": Call(Sig((), TEXT)),
            "foobar": Call(Sig(("int",), TEXT)),
        }
    )

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        def match(pattern: Any, s: bytes) -> int:
            # the text up to its first zero byte, as the tests module reads it
            return int(pattern.run(s.split(b"\x00", 1)[0]))

        return {
            "constants": {"one": 1, "two": 2, "foo": b"foo", "empty": b""},
            "undefined": {},
            "integer_array": {0: 0, 1: 1, 2: 2, 256: 256},
            "string_array": {0: b"foo", 1: b"bar", 2: b"baz", 3: b"foo\x00bar"},
            "integer_dict": {},
            "string_dict": {b"foo": b"foo", b"bar": b"bar"},
            "struct_array": {1: {"i": 1}},
            "struct_dict": {b"foo": {"i": 1, "s": b"foo"}},
            "empty_struct_dict": {},
            "empty_struct_array": {},
            "match": (match,),
            "isum": (lambda a, b: a + b, lambda a, b, c: a + b + c),
            "fsum": (lambda a, b: float(a + b), lambda a, b, c: float(a + b + c)),
            "length": (len,),
            "empty": (lambda: b"",),
            "foobar": (lambda n: b"foo" if n == 1 else b"bar" if n == 2 else b"oops",),
        }

    MODULE: ClassVar[Module] = Module(SCHEMA, data)

    @staticmethod
    def outcome(rule: str, data: bytes) -> str:
        try:
            rules = Rules.compile(rule, ReferenceSuite.EXTERNALS, {"tests": ReferenceSuite.MODULE})
        except RuleError:
            return "error"
        return "true" if rules.match(data, timeout=20) else "false"


class TestTheReferenceSuite:
    @pytest.mark.parametrize("index", range(len(ReferenceSuite.CASES)))
    def test_each_case_comes_out_as_the_suite_says(self, index: int) -> None:
        case = ReferenceSuite.CASES[index]
        got = ReferenceSuite.outcome(case["rule"], base64.b64decode(case["data"]))
        assert got == case["expect"], case["rule"]


class TestTheTestsModule:
    def test_its_data_fits_its_declaration(self) -> None:
        assert Data.conforms(ReferenceSuite.SCHEMA, ReferenceSuite.data(b"")) == []


class TypeChecking:
    """A battery of typed conditions: every operator over every pairing of value kinds, plus each
    construct that takes a typed operand. `data/rule_reference/type-checking.json` records whether
    the reference engine compiles each (its `about` says how)."""

    VALUES: ClassVar[dict[str, str]] = {
        "int": "1", "float": "1.5", "text": '"a"', "bool": "true", "uint": "uint8(0)",
        "fsz": "filesize", "undef_int": "tests.undefined.i", "mint": "tests.constants.one",
        "mtext": "tests.constants.foo", "mfloat": "tests.undefined.f", "struct": "tests.constants",
        "array": "tests.integer_array", "dict": "tests.string_dict", "func": "tests.isum",
    }  # fmt: skip
    BINARY: ClassVar[list[str]] = [
        "+", "-", "*", "\\", "%", "&", "|", "^", "<<", ">>", "==", "!=", "<", ">", "<=", ">=",
        "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals",
        "and", "or",
    ]  # fmt: skip
    FORMS: ClassVar[list[str]] = [
        "-{}", "~{}", "not {}", "defined {}", "{} matches /a/", "uint8({})", "@s[{}] == 1",
        "!s[{}] == 1", "#s in ({}..2) == 1", "$s at {}", "$s in ({}..2)", "$s in (0..{})",
        "{} of them", "{}% of them", "for {} i in (1..2) : (true)", "for any i in ({}..2) : (true)",
        "for any i in (1..{}) : (true)", "for any i in ({}, {}) : (true)",
        "for any i in {} : (true)", "for any k, v in {} : (true)", "tests.integer_array[{}] == 1",
        'tests.string_dict[{}] == "a"', "tests.isum({}, 1) == 1", "tests.match(/a/, {}) == 1",
        "{}", "({}) == 1", "filesize == {}", "{} == {}",
    ]  # fmt: skip
    WRAP: ClassVar[str] = (
        'import "tests" rule r {{ strings: $s = "a" condition: #s >= 0 and ({}) }}'
    )
    EXPECTED: ClassVar[dict[str, Any]] = json.loads(
        (ROOT / "tests" / "unit" / "data" / "rule_reference" / "type-checking.json").read_text(
            encoding="utf-8"
        )
    )

    @staticmethod
    def cases() -> list[str]:
        out: list[str] = []
        for op in TypeChecking.BINARY:
            for x in TypeChecking.VALUES.values():
                for y in TypeChecking.VALUES.values():
                    out += [
                        f"({x} {op} {y})",
                        f"(({x} {op} {y}) == 1)",
                        f'(({x} {op} {y}) == "a")',
                        f"(({x} {op} {y}) == 1.5)",
                    ]
        for x in TypeChecking.VALUES.values():
            out += [form.replace("{}", x) for form in TypeChecking.FORMS]
            out.append(f'true or ({x} + "a" == 1)')
        out += [f"for any i in (1..2) : ({v} == 1)" for v in ("i", "k")]
        return list(dict.fromkeys(out))

    @staticmethod
    def compiles(condition: str) -> bool:
        try:
            Rules.compile(
                TypeChecking.WRAP.format(condition), modules={"tests": ReferenceSuite.MODULE}
            )
        except RuleError:
            return False
        return True


class TestTypeChecking:
    def test_the_battery_is_the_one_the_reference_answered(self) -> None:
        cases, expected = TypeChecking.cases(), TypeChecking.EXPECTED
        assert (len(cases), cases[0], cases[-1]) == (
            expected["count"],
            expected["first"],
            expected["last"],
        )

    def test_every_case_compiles_exactly_when_the_reference_compiles_it(self) -> None:
        bits = base64.b64decode(TypeChecking.EXPECTED["compiles"])
        wrong = [
            (condition, want)
            for i, condition in enumerate(TypeChecking.cases())
            if TypeChecking.compiles(condition) != (want := bool(bits[i >> 3] >> (i & 7) & 1))
        ]
        assert wrong == [], f"{len(wrong)} differ, first: {wrong[:5]}"


class TestMatches:
    """Behaviour checked against the reference engine when this was written."""

    @pytest.mark.parametrize(
        ("rule", "data", "offsets"),
        [
            (
                "rule r { strings: $a = /a+/ condition: $a }",
                b"aaaa",
                [(0, 4), (1, 3), (2, 2), (3, 1)],
            ),
            ('rule r { strings: $a = "aa" condition: $a }', b"aaaa", [(0, 2), (1, 2), (2, 2)]),
            (
                "rule r { strings: $a = { 61 [0-2] 62 } condition: $a }",
                b"aaab",
                [(0, 4), (1, 3), (2, 2)],
            ),
            (
                'rule r { strings: $a = "ab" fullword condition: $a }',
                b"ab xab ab_ ab.",
                [(0, 2), (7, 2), (11, 2)],
            ),
            (
                'rule r { strings: $a = "ab" wide ascii condition: $a }',
                b"ab a\x00b\x00",
                [(0, 2), (3, 4)],
            ),
            (
                'rule r { strings: $a = "Ab" nocase condition: $a }',
                b"ab AB aB",
                [(0, 2), (3, 2), (6, 2)],
            ),
        ],
    )
    def test_every_start_is_a_match_as_the_reference_reports(
        self, rule: str, data: bytes, offsets: list
    ) -> None:
        (match,) = Rules.compile(rule).match(data)
        assert [(at, len(text)) for at, _, text in match.strings] == offsets

    def test_base64_at_every_alignment(self) -> None:
        rule = Rules.compile('rule r { strings: $a = "This program cannot" base64 condition: $a }')
        for prefix in (b"", b"z", b"zz"):
            assert rule.match(base64.b64encode(prefix + b"This program cannot be run"))


class Counted(Mapping[int, Any]):
    """An array that counts the items read from it, as a table that decodes on access would."""

    def __init__(self, items: dict[int, Any]) -> None:
        self.items, self.reads = items, 0

    def __getitem__(self, i: int) -> Any:
        value = self.items[i]  # an absent slot raises before it counts as read
        self.reads += 1
        return value

    def __iter__(self) -> Iterator[int]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)


class TestLoopsOverLazyArrays:
    @staticmethod
    def module(items: Counted) -> Module:
        schema = Record({"items": Seq(Scalar.INT)})
        return Module(schema, lambda file: {"items": items})

    def test_each_element_is_read_once_and_only_by_the_loop(self) -> None:
        items = Counted({0: 1, 1: 2, 3: 4})  # slot 2 not filled: undefined
        rules = Rules.compile(
            'import "lazy" rule r { condition: for 3 x in lazy.items : (x > 0) }',
            modules={"lazy": TestLoopsOverLazyArrays.module(items)},
        )
        assert rules.match(b"")  # 1, 2 and 4 count; the empty slot is undefined, not true
        assert items.reads == 3  # each filled slot read once, the gap never decoded

    def test_a_long_loop_reads_each_element_once(self) -> None:
        items = Counted({i: i for i in range(1000)})
        rules = Rules.compile(
            'import "lazy" rule r { condition: for 0 x in lazy.items : (false) }',
            modules={"lazy": TestLoopsOverLazyArrays.module(items)},
        )
        assert rules.match(b"")
        assert items.reads == 1000  # the loop reads each element as it reaches it, once


class TestAtOffsets:
    """The offset after `at` is a whole arithmetic expression, as the reference's grammar reads
    it (signature collections write `$name at @crc[1] + 16`); a comparison or `and` ends it."""

    def test_arithmetic_after_at_is_the_offset(self) -> None:
        rules = Rules.compile(
            'rule r { strings: $c = "C" $n = "N" condition: $n at @c[1] + 2 * 2 }'
        )
        assert rules.match(b"xC123N")
        assert not rules.match(b"xC12N")

    def test_and_ends_the_offset(self) -> None:
        rules = Rules.compile('rule r { strings: $a = "A" condition: $a at 1 + 1 and #a == 1 }')
        assert rules.match(b"xxA")
        assert not rules.match(b"xxAA")

    def test_of_at_takes_the_whole_expression_too(self) -> None:
        rules = Rules.compile('rule r { strings: $a = "A" condition: any of them at 1 + 1 }')
        assert rules.match(b"xxA")
        assert not rules.match(b"xA")

    def test_a_test_after_at_is_refused(self) -> None:
        with pytest.raises(RuleError, match="at takes a value"):
            Rules.compile('rule r { strings: $a = "A" condition: $a at not true }')


class TestHostileInput:
    def test_a_whitespace_flood_does_not_make_a_regex_slow(self) -> None:
        rules = Rules.compile(r"rule r { strings: $a = /\s*\(/ condition: $a }")
        # CPU time: the work runs in this process, so a loaded machine does not stretch it.
        started = time.process_time()
        assert not rules.match(b" " * 2_000_000, timeout=60)
        assert time.process_time() - started < 60

    def test_an_expression_re_would_backtrack_on_runs_on_the_linear_engine(self) -> None:
        rules = Rules.compile(r"rule r { strings: $a = /(\s*,\s*\d{1,3}){19,}x/ condition: $a }")
        # CPU time: the work runs in this process, so a loaded machine does not stretch it.
        started = time.process_time()
        assert not rules.match(b"1" + b" , 1" * 5000 + b"y", timeout=60)
        assert time.process_time() - started < 60

    def test_the_deadline_stops_matching(self) -> None:
        rules = Rules.compile("rule r { strings: $a = { 61 [-] 62 } condition: $a }")
        with pytest.raises(RuleError, match="longer than the time allowed"):
            rules.match(b"a" * 3_000_000, timeout=0.001)

    def test_includes_are_refused(self) -> None:
        with pytest.raises(RuleError, match="include"):
            Rules.compile('include "x.yar"\nrule r { condition: true }')


class TestIncludes:
    """`include` reads files under one root, relative to the including file, as the reference
    does; it never reads outside the root, follows a cycle, or exceeds the byte budget."""

    @staticmethod
    def tree(root: Path, files: dict[str, str]) -> None:
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)

    def test_an_index_includes_its_members_relative_to_each_file(self, tmp_path: Path) -> None:
        self.tree(
            tmp_path,
            {
                "index.yar": 'include "./malware/a.yar"\nrule top { condition: a and b }',
                "malware/a.yar": 'include "../utils/b.yar"\nrule a { condition: true }',
                "utils/b.yar": "private rule b { condition: true }",
            },
        )
        top = tmp_path / "index.yar"
        rules = Rules.compile(top.read_text(), includes=Includes(tmp_path, top=top))
        assert [r.name for r in rules.rules] == ["b", "a", "top"]
        assert [m.rule for m in rules.match(b"x")] == ["a", "top"]

    def test_a_file_outside_the_root_is_refused(self, tmp_path: Path) -> None:
        self.tree(
            tmp_path, {"c/index.yar": 'include "../x.yar"', "x.yar": "rule x { condition: true }"}
        )
        top = tmp_path / "c" / "index.yar"
        with pytest.raises(RuleError, match="outside the rule collection"):
            Rules.compile(top.read_text(), includes=Includes(top.parent, top=top))

    def test_a_link_out_of_the_root_is_refused(self, tmp_path: Path) -> None:
        self.tree(
            tmp_path, {"c/index.yar": 'include "link.yar"', "x.yar": "rule x { condition: true }"}
        )
        (tmp_path / "c" / "link.yar").symlink_to(tmp_path / "x.yar")
        top = tmp_path / "c" / "index.yar"
        with pytest.raises(RuleError, match="outside the rule collection"):
            Rules.compile(top.read_text(), includes=Includes(top.parent, top=top))

    def test_an_absolute_name_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(RuleError, match="an absolute path"):
            Rules.compile('include "/etc/other.yar"', includes=Includes(tmp_path))

    def test_a_cycle_is_refused(self, tmp_path: Path) -> None:
        self.tree(tmp_path, {"a.yar": 'include "b.yar"', "b.yar": 'include "a.yar"'})
        top = tmp_path / "a.yar"
        with pytest.raises(RuleError, match="an include cycle"):
            Rules.compile(top.read_text(), includes=Includes(tmp_path, top=top))

    def test_the_byte_budget_covers_every_included_file(self, tmp_path: Path) -> None:
        self.tree(tmp_path, {"a.yar": "rule a { condition: true }" + " " * 100})
        with pytest.raises(RuleError, match="over the size limit"):
            Rules.compile('include "a.yar"', includes=Includes(tmp_path, max_bytes=64))

    def test_the_closure_lists_every_file_read_at_any_depth(self, tmp_path: Path) -> None:
        self.tree(
            tmp_path,
            {
                "a.yar": 'include "b/c.yar"',
                "b/c.yar": 'include "d.yar"',
                "b/d.yar": "rule d { condition: true }",
            },
        )
        top = tmp_path / "a.yar"
        read = Includes(tmp_path, top=top).closure(top.read_text())
        assert read == [tmp_path.resolve() / "b" / "c.yar", tmp_path.resolve() / "b" / "d.yar"]

    def test_an_error_in_an_included_file_names_that_file(self, tmp_path: Path) -> None:
        self.tree(tmp_path, {"bad.yar": "rule a { condition: $x }"})
        with pytest.raises(RuleError, match="undefined string"):
            Rules.compile('include "bad.yar"', includes=Includes(tmp_path))
        self.tree(tmp_path, {"worse.yar": "rule a { condition: true and }"})
        with pytest.raises(RuleError, match=r"worse\.yar line 1"):
            Rules.compile('include "worse.yar"', includes=Includes(tmp_path))
