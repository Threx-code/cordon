"""rule_engine.gates.Gates.hold: each distinct gate runs once per file, and every rule's result
is the one running every gate would give. Random rule sets sharing gates (leading bytes,
filesize, a module's value, another rule's result, a loop) both ways on random files; a gate
shared by many rules asked once; a gate naming another rule never kept."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine.gates import Gates
from cordon_scanner.detect.binary.rule_engine.lang import Rules

GATE = st.sampled_from(
    [
        "uint16(0) == 0x5A4D", "uint8(0) == 0x61", "filesize < 40", "filesize > 3",
        "uint8(1) != 0x62", "math.entropy(0, filesize) > 1.0", "r0", "not r1",
        "for any i in (0..2) : (uint8(i) == 0x61)", "uint16be(0) == 0x6162",
    ]
)  # fmt: skip
DATA = st.lists(st.sampled_from([b"a", b"b", b"MZ", b"ab", b"\x00", b"x"]), max_size=40).map(
    b"".join
)


class Both:
    @staticmethod
    def matches(source: str, data: bytes, memo: bool, monkeypatch: pytest.MonkeyPatch) -> object:
        if not memo:
            monkeypatch.setattr(
                Gates,
                "hold",
                staticmethod(lambda rule, frame, held: all(g(frame) for g in rule.gates)),
            )
        try:
            return sorted((m.rule, sorted(m.strings)) for m in Rules.compile(source).match(data))
        finally:
            monkeypatch.undo()


class TestTheSameResults:
    @settings(max_examples=1000, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        gates=st.lists(st.lists(GATE, min_size=1, max_size=3), min_size=2, max_size=6), data=DATA
    )
    def test_kept_and_run_every_time_agree(
        self, gates: list[list[str]], data: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rules = []
        for i, gs in enumerate(gates):
            gs = [
                g
                for g in gs
                if g not in (f"r{i}", f"not r{i}")
                and not (g.lstrip("not ").startswith("r") and int(g[-1]) >= i)
            ]
            cond = " and ".join([*gs, "$s"]) if gs else "$s"
            rules.append(f'rule r{i} {{ strings: $s = "a" condition: {cond} }}')
        source = 'import "math"\n' + "\n".join(rules)
        assert Both.matches(source, data, True, monkeypatch) == Both.matches(
            source, data, False, monkeypatch
        )


class TestOnce:
    def test_a_gate_many_rules_share_is_asked_once(self) -> None:
        source = "\n".join(
            f'rule r{i} {{ strings: $s = "MZ{i}" condition: uint16(0) == 0x5A4D and $s }}'
            for i in range(50)
        )
        rules = Rules.compile(source)
        calls = [0]
        for rule in rules.rules:
            gate = rule.gates[0]

            def counted(frame: Any, gate: Any = gate) -> bool:
                calls[0] += 1
                return bool(gate(frame))

            rule.gates = [counted]
        found = rules.match(b"MZ" + b"".join(b"MZ%d" % i for i in range(50)))
        assert len(found) == 50 and calls[0] == 1

    def test_a_gate_naming_a_rule_is_not_kept(self) -> None:
        rules = Rules.compile(
            'rule a { condition: true }\nrule b { strings: $s = "x" condition: a and $s }'
        )
        assert rules.rules[1].gate_keys == [None]
