"""The bundled patterns' derivation table (item 74, cut 3): it matches a live derivation exactly, and it
is never read when it could be wrong."""

from __future__ import annotations

import json
import re

import pytest

from cordon_scanner.rules.derivations import SUPPORTED, PatternDerivations
from cordon_scanner.rules.loader import RuleLoader
from cordon_scanner.rules.patterns import PatternCompiler


class DerivationKit:
    @staticmethod
    def shipped_document() -> dict:
        return json.loads(
            (PatternDerivations.directory() / PatternDerivations.table()).read_text(
                encoding="utf-8"
            )
        )

    @staticmethod
    def use(monkeypatch: pytest.MonkeyPatch, entries: dict) -> None:
        monkeypatch.setattr(PatternDerivations, "shipped", staticmethod(lambda: entries))


class TestTheShippedTableIsCurrent:
    def test_it_equals_a_live_derivation_of_every_bundled_pattern(self) -> None:
        shipped = DerivationKit.shipped_document()
        assert shipped == PatternDerivations.document(*RuleLoader.bundled_patterns()), (
            f"rules/builtin/{PatternDerivations.table()} is out of date: a bundled pack or "
            "rules/patterns.py changed. Regenerate every Python's table in the same commit (see "
            "scripts/build/build_rule_derivations.py)"
        )

    def test_it_ships_beside_the_bundled_packs(self) -> None:
        assert PatternDerivations.directory() == RuleLoader.builtin_pack_dir()

    def test_every_bundled_pack_still_compiles_eagerly(self) -> None:
        # A bad pattern fails CI here, not on a user's first matching file: the table never skips
        # compiling, only the safety walk of a pattern recorded as safe.
        for pack in RuleLoader._load_builtin(RuleLoader(), RuleLoader.builtin_pack_dir()):
            for compiled in pack.rules:
                if compiled.match.regex is not None:
                    pattern = compiled.match.regex.pattern.decode("utf-8")
                    PatternCompiler.validate_pattern(pattern, rule_id=compiled.rule.id)


class TestItIsNeverReadWhenItCouldBeWrong:
    def test_other_derivation_code_drops_the_whole_table(self, monkeypatch, tmp_path) -> None:
        doc = DerivationKit.shipped_document()
        doc["code"] = "0" * 64
        (tmp_path / PatternDerivations.table()).write_text(json.dumps(doc), encoding="utf-8")
        monkeypatch.setattr(PatternDerivations, "directory", staticmethod(lambda: tmp_path))
        assert PatternDerivations.shipped.__wrapped__() == {}

    def test_another_python_drops_the_whole_table(self, monkeypatch, tmp_path) -> None:
        doc = DerivationKit.shipped_document()
        doc["python"] = "2.7"
        (tmp_path / PatternDerivations.table()).write_text(json.dumps(doc), encoding="utf-8")
        monkeypatch.setattr(PatternDerivations, "directory", staticmethod(lambda: tmp_path))
        assert PatternDerivations.shipped.__wrapped__() == {}

    def test_a_missing_or_unreadable_table_is_no_table(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(PatternDerivations, "directory", staticmethod(lambda: tmp_path))
        assert PatternDerivations.shipped.__wrapped__() == {}
        (tmp_path / PatternDerivations.table()).write_text("{not json", encoding="utf-8")
        assert PatternDerivations.shipped.__wrapped__() == {}


class TestAPatternTheTableDoesNotHold:
    def test_is_derived_live(self, monkeypatch) -> None:
        DerivationKit.use(monkeypatch, {})
        pattern = r"\bxmrig\b"
        assert PatternDerivations.literals(
            pattern, "required"
        ) == PatternCompiler.required_literals(pattern)
        assert PatternDerivations.prefilter(pattern) == PatternCompiler._extract_prefilter(
            pattern.encode("utf-8")
        )

    def test_an_unsafe_pattern_is_still_refused(self, monkeypatch) -> None:
        from cordon_scanner.foundation.errors import UnsafePatternError

        DerivationKit.use(monkeypatch, {})
        with pytest.raises(UnsafePatternError):
            PatternDerivations.validated("((a+))+$", rule_id="T")

    def test_the_table_never_records_an_unsafe_pattern(self) -> None:
        derived = PatternDerivations.derive([], ["((a+))+$"])
        assert derived == {}

    def test_a_safe_entry_compiles_as_validation_does(self, monkeypatch) -> None:
        pattern = r"(?:curl)|(?:wget)"
        DerivationKit.use(monkeypatch, {PatternDerivations.key(pattern): {"safe": True}})
        live = PatternCompiler.validate_pattern(pattern, rule_id="T")
        stored = PatternDerivations.validated(pattern, rule_id="T")
        assert (stored.pattern, stored.flags) == (live.pattern, live.flags)
        assert stored.flags & re.MULTILINE


class TestEverySupportedPythonHasItsTable:
    """One table per supported Python: on one without its own, every pattern took the full safety walk
    at load (3.13 and 3.14 read the 3.12 table as another Python's and ignored it)."""

    @pytest.mark.parametrize("python", SUPPORTED)
    def test_a_table_is_shipped_for_it(self, python: str) -> None:
        document = json.loads(
            (PatternDerivations.directory() / PatternDerivations.table(python)).read_text(
                encoding="utf-8"
            )
        )
        assert document["python"] == python
        assert document["code"] == PatternDerivations.code_digest()

    def test_the_running_python_is_supported(self) -> None:
        assert PatternDerivations.python() in SUPPORTED
