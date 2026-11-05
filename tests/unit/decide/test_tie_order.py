"""The five sorts #32 made total (50f2708d) never changed an answer the verdict features read.

Before #32 each sorted a set on a key that called distinct elements equal (a length, a version the
ecosystem calls equal), so equal elements kept the set's order, which follows the hash seed. The fit
reads rows written before #32 (P8's, 7947e539), so their features are valid only if no answer
depended on that order (architecture item B: the row-validity tool's `ties` check runs these tests).

Each test runs the real code on tied inputs with the module's `sorted` replaced by the old one: the
input shuffled (any set order), then sorted stably on the old key, which is the first part of the
new one. Every one of `ROUNDS` shuffles must give the answer the total sort gives.
"""

from __future__ import annotations

import builtins
import random
from typing import Any, ClassVar

import pytest

from cordon_scanner.analysis.shared import deobfuscation
from cordon_scanner.analysis.shared.deobfuscation import ObfuscatorIo, Resolver
from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.supply import reachability
from cordon_scanner.detect.supply.advisories import detector as advisories
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.detect.supply.reachability import ImportReachability
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.foundation.text import literals
from cordon_scanner.foundation.text.literals import LiteralGate
from cordon_scanner.intel.advisories import nvd
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase
from cordon_scanner.intel.advisories.nvd import CpeRule
from cordon_scanner.rules.loader import RuleLoader, RuleSet

RULES = RuleSet(RuleLoader.load_builtin())


class OldOrder:
    """`sorted` as it was: any order among elements the old key called equal."""

    ROUNDS: ClassVar[int] = 300

    @staticmethod
    def sorted_like_before(rng: random.Random, shuffled: list[int]):
        def old(iterable: Any, key: Any = None, reverse: bool = False) -> list[Any]:
            items = list(iterable)
            if key is None or not items or not isinstance(key(items[0]), tuple):
                return builtins.sorted(items, key=key, reverse=reverse)
            rng.shuffle(items)
            shuffled[0] += 1
            return builtins.sorted(items, key=lambda x: key(x)[0], reverse=reverse)

        return old

    @staticmethod
    def every_order(monkeypatch: pytest.MonkeyPatch, module: Any, run: Any) -> None:
        """`run()` gives the total sort's answer, then the same answer under every shuffle; and
        the old sort really ran, every round (a site that stopped sorting would pass vacuously)."""
        want = run()
        rng = random.Random(32)  # noqa: S311 -- a fixture, not key material
        shuffled = [0]
        monkeypatch.setitem(module.__dict__, "sorted", OldOrder.sorted_like_before(rng, shuffled))
        for _ in range(OldOrder.ROUNDS):
            assert run() == want
        monkeypatch.delitem(module.__dict__, "sorted")
        assert shuffled[0] >= OldOrder.ROUNDS, "the old sort never ran: the site changed"


class EchoResolver(Resolver):
    """Every decoder and wrapper name resolves, to its own name and arguments."""

    def __init__(self, names: list[str]) -> None:
        super().__init__(names[0], 0, "plain", [], {n: ([], n, []) for n in names[1:]})

    def resolve(self, fn: str, args: tuple[float | str, ...], depth: int = 0) -> str | None:
        return f"{fn}:{args}"


class TestTheTiesNeverMoved:
    def test_the_deobfuscators_call_alternation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Eight names of one length, three of another: every one is a call in the text.
        names = [
            "_0xa1b2",
            "_0xc3d4",
            "_0xe5f6",
            "_0x0718",
            "_0x293a",
            "_0x4b5c",
            "_0x6d7e",
            "_0x8f90",
            "_0xab",
            "_0xcd",
            "_0xef",
        ]
        text = " ".join(f"{n}(0x{i:x}, 'k{i}'); x.{n}(1);" for i, n in enumerate(names * 3))
        resolver = EchoResolver(names)
        OldOrder.every_order(
            monkeypatch, deobfuscation, lambda: ObfuscatorIo._substitute(text, resolver)
        )

    def test_reachabilitys_binding_alternation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        text = (
            "import { alpha, bravo, delta, gamma as omega } from 'pkg-one';\n"
            "import * as kilo from 'pkg-two';\nimport lima from 'pkg-three';\n"
            "alpha.run(); bravo(); omega.x.y; kilo.z(); lima(); delta; alphabet; xalpha;\n"
        )

        def run() -> dict[str, Any]:
            usage: dict[str, Any] = {}
            ImportReachability._js_usage(text, usage, {})
            return {k: vars(v) for k, v in usage.items()}

        OldOrder.every_order(monkeypatch, reachability, run)

    def test_the_literal_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rng = random.Random(7)  # noqa: S311 -- a fixture, not key material
        alphabet = b"abcdef"
        pool = [bytes(rng.choice(alphabet) for _ in range(rng.randint(3, 7))) for _ in range(60)]
        data = [bytes(rng.choice(alphabet) for _ in range(400)) for _ in range(40)]

        def run() -> tuple[Any, ...]:
            gate = LiteralGate(pool)
            return (
                frozenset(gate.literals),
                frozenset(gate.core or ()),
                tuple(gate.present(d) for d in data),
            )

        OldOrder.every_order(monkeypatch, literals, run)

    def test_nvds_one_project_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Two products of one vendor, equal-length names, on one project site; and a third that
        # contains one of them, on the same site.
        cases = [
            {
                "x:abcd": ["github.com/acme/abcd"],
                "x:wxyz": ["github.com/acme/abcd"],
            },
            {
                "acme:curl": ["github.com/acme/curl"],
                "acme:libcurl": ["github.com/acme/curl"],
                "acme:lurc": ["github.com/acme/curl"],
            },
        ]

        def run() -> tuple[Any, ...]:
            out = []
            for case in cases:
                index = {"k": [(product, refs) for product, refs in case.items()]}
                out.append(
                    CpeRule.by_project_site(index, {"github.com/acme/abcd", "github.com/acme/curl"})
                )
            return tuple(out)

        OldOrder.every_order(monkeypatch, nvd, run)

    def test_the_advisorys_upgrade_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Two records naming one release two ways ("1.3", "1.3.0"): the old sort kept either
        # first, and the remediation named it. What the rows record never moved.
        records = (
            Advisory(
                ecosystem="maven",
                name="org.example:lib",
                versions=("1.2", "1.3"),
                summary="s",
                identifier="GHSA-aaaa-bbbb-cccc",
            ),
            Advisory(
                ecosystem="maven",
                name="org.example:lib",
                versions=("1.2", "1.3.0"),
                summary="s",
                identifier="GHSA-dddd-eeee-ffff",
            ),
        )
        dependency = Dependency(
            ecosystem="maven",
            name="org.example:lib",
            version="1.2",
            purl="pkg:maven/org.example/lib@1.2",
        )

        def run() -> tuple[Any, ...]:
            ctx = ScanContext(config=Config.default(), rules=RULES)
            found = AdvisoryDetector(AdvisoryDatabase(records)).inspect(
                GraphUnit(dependencies=(dependency,)), ctx
            )
            return tuple(
                sorted(
                    (
                        f.rule_id,
                        int(f.severity),
                        int(f.confidence),
                        str(f.category),
                        f.location.path,
                        f.location.package,
                    )
                    for f in found
                )
            )

        OldOrder.every_order(monkeypatch, advisories, run)

    def test_the_harness_sees_an_answer_that_does_follow_the_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The remediation did name whichever spelling came first: the same shuffles must catch it.
        records = (
            Advisory(
                ecosystem="maven",
                name="org.example:lib",
                versions=("1.2", "1.3"),
                summary="s",
                identifier="GHSA-aaaa-bbbb-cccc",
            ),
            Advisory(
                ecosystem="maven",
                name="org.example:lib",
                versions=("1.2", "1.3.0"),
                summary="s",
                identifier="GHSA-dddd-eeee-ffff",
            ),
        )
        dependency = Dependency(
            ecosystem="maven",
            name="org.example:lib",
            version="1.2",
            purl="pkg:maven/org.example/lib@1.2",
        )

        def run() -> tuple[str, ...]:
            ctx = ScanContext(config=Config.default(), rules=RULES)
            found = AdvisoryDetector(AdvisoryDatabase(records)).inspect(
                GraphUnit(dependencies=(dependency,)), ctx
            )
            return tuple(sorted(f.remediation for f in found))

        with pytest.raises(AssertionError):
            OldOrder.every_order(monkeypatch, advisories, run)
