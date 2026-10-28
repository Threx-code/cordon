"""The PE reader (rule_pe) against the reference engine's recorded values for the real-file fixtures. The
reader returns plain, schema-shaped data; recode() renders it the way the reference reports a module (bytes
as hex, a sequence as its set slots in order, integers signed) so the two compare leaf by leaf. The
malformed-file and full-corpus differentials live in the review harness; these fixtures pin the values a
change must not move, and conformance to the declared schema is checked alongside.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_lang import Rules
from cordon_scanner.detect.binary.rule_pe import Pe
from cordon_scanner.detect.binary.rule_values import Call, Data, Keyed, Record, Scalar, Seq
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
EXPECTED: dict[str, Any] = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
FUNCTIONS: dict[str, Any] = json.loads((DIR / "functions.json").read_text(encoding="utf-8"))
PE_FIXTURES = sorted(n for n, e in EXPECTED.items() if (e["modules"].get("pe") or {}).get("is_pe"))
ALL_UNDEFINED = "libffi-raw_api.o"  # not a PE: every pe.* call is undefined


class Tree:
    """Schema-shaped data rendered and flattened the way the reference reports a module, for comparison."""

    @staticmethod
    def recode(declared: Any, data: Any) -> Any:
        if data is None or isinstance(declared, Call):
            return None
        if isinstance(declared, Scalar):
            if declared is Scalar.TEXT:
                return {"b": data.hex()}
            if declared is Scalar.INT:
                v = data & ((1 << 64) - 1)
                return v - (1 << 64) if v >> 63 else v
            return data
        if isinstance(declared, Record):
            out = {}
            for k, kind in declared.fields.items():
                if k in data and data[k] is not None:
                    r = Tree.recode(kind, data[k])
                    if r is not None:
                        out[k] = r
            return out
        if isinstance(declared, Seq):
            return [Tree.recode(declared.item, v) for _k, v in sorted(data.items())]
        if isinstance(declared, Keyed):
            return {k.decode("latin-1"): Tree.recode(declared.item, v) for k, v in data.items()}
        return data

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict) and "b" not in v:
            for k, x in v.items():
                Tree.leaves(x, f"{prefix}.{k}" if prefix else k, out)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                Tree.leaves(x, f"{prefix}[{i}]", out)
            out[prefix + "#len"] = len(v)
        else:
            out[prefix] = v
        return out


class TestPeValues:
    @pytest.mark.parametrize("name", PE_FIXTURES)
    def test_every_value_is_the_one_the_reference_gives(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        expected = EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        want = Tree.leaves(expected["modules"]["pe"], "", {})
        got = Tree.leaves(Tree.recode(Pe.SCHEMA, Pe.data(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []

    @pytest.mark.parametrize("name", PE_FIXTURES)
    def test_conforms_to_the_declared_schema(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        assert Data.conforms(Pe.SCHEMA, Pe.data(data)) == []


class TestPeBasics:
    def test_not_a_pe_is_zero_with_everything_else_absent(self) -> None:
        d = Pe.data(b"plain text, not an executable at all")
        assert d["is_pe"] == 0
        assert "machine" not in d  # an undefined field is omitted, not a sentinel
        assert d["sections"] == {}

    def test_short_mz_does_not_crash(self) -> None:
        assert Pe.data(b"MZ" + b"\x00" * 100)["is_pe"] == 0


class TestPeFunctions:
    """Every module function the reference recorded for a fixture must come back byte-identical from our
    engine -- exact values, not kinds, so a wrong value turns the suite red. Two recorded datasets, both
    run through the engine exactly as the reference captured them (one console.log rule per call):

    - expected.json's ``functions`` -- what the reference engine's modules_callback reports for each file (imphash,
      the predicates, imports/exports/section/rva with real arguments, rich_signature.toolid/version, and
      elf.telfhash/import_md5 for the object file);
    - functions.json -- the broader harness set: 33 varied calls (absent names, out-of-range RVAs, ordinal,
      regex and delayed forms) plus per-file hitting arguments (a real imported dll/function, a real export,
      a real section, an in-section RVA), with libffi-raw_api.o as a file where every pe.* call is undefined.

    functions.json is generated by scratch/fnpin (gen_args.py + run_funcs.py) and validated ours==reference;
    the modules README records how."""

    @staticmethod
    def _console(src: str, data: bytes) -> list[str]:
        logs: list[str] = []
        Rules.compile(src).match(data, console=logs.append)
        return logs

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_recorded_function_values_match_the_reference(self, name: str) -> None:
        fns = EXPECTED[name]["functions"]
        exprs = sorted(fns)
        src = 'import "pe"\nimport "elf"\nimport "console"\n' + "\n".join(
            f'rule q{i} {{ condition: console.log("{i}=", {expr}) }}'
            for i, expr in enumerate(exprs)
        )
        got: dict[str, str] = {}
        for line in self._console(src, (DIR / name).read_bytes()):
            idx, _, value = line.partition("=")
            got[exprs[int(idx)]] = value
        assert got == {expr: str(fns[expr]) for expr in exprs}

    @pytest.mark.parametrize("name", sorted(FUNCTIONS))
    def test_call_coverage_matches_the_reference(self, name: str) -> None:
        entry = FUNCTIONS[name]
        src = 'import "pe"\nimport "console"\n' + "\n".join(
            f'rule r{i} {{ condition: console.log("{lbl}=", {expr}) }}'
            for i, (lbl, expr) in enumerate(entry["calls"])
        )
        assert sorted(self._console(src, (DIR / name).read_bytes())) == entry["logs"]
        if (
            name in PE_FIXTURES
        ):  # a PE must pin real values, so an empty recording cannot pass silently
            assert len(entry["logs"]) > 20

    def test_a_non_pe_file_leaves_every_pe_call_undefined(self) -> None:
        src = 'import "pe"\nimport "console"\n' + "\n".join(
            f'rule r{i} {{ condition: console.log("{lbl}=", {expr}) }}'
            for i, (lbl, expr) in enumerate(FUNCTIONS[ALL_UNDEFINED]["calls"])
        )
        assert self._console(src, (DIR / ALL_UNDEFINED).read_bytes()) == []
        assert FUNCTIONS[ALL_UNDEFINED]["logs"] == []
