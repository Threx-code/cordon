"""The match cache (rule_engine/match_cache.py): the same bytes are matched once per rule set, an
entry is used only when its signature verifies, and rules whose answer can change between scans are
never kept."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cordon_scanner.detect.binary.rule_engine.lang import Match, Rules
from cordon_scanner.detect.binary.rule_engine.match_cache import MatchCache

RULES = 'rule r { meta: n = 1 s = "x" b = true strings: $a = "needle" condition: $a }'


class Kit:
    @staticmethod
    def write(tmp_path: Path, text: str = RULES, name: str = "r.yar") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    @staticmethod
    def identity(path: Path, imports: frozenset[str] = frozenset()) -> str:
        found = MatchCache.identity([path], (), imports)
        assert found is not None
        return found


class TestMatchCache:
    def test_kept_matches_come_back_identical(self, tmp_path: Path) -> None:
        cache = MatchCache(tmp_path / "m")
        rules = Rules.compile(RULES)
        data = b"a needle in hay"
        found = list(rules.match(data))
        ident = Kit.identity(Kit.write(tmp_path))
        cache.put(ident, data, found)
        assert cache.get(ident, data) == found
        assert cache.hits == 1
        assert isinstance(found[0], Match) and found[0].strings == [(2, "$a", b"needle")]

    def test_other_bytes_are_a_miss(self, tmp_path: Path) -> None:
        cache = MatchCache(tmp_path / "m")
        ident = Kit.identity(Kit.write(tmp_path))
        cache.put(ident, b"one", [])
        assert cache.get(ident, b"two") is None

    def test_a_changed_rule_or_included_file_is_another_identity(self, tmp_path: Path) -> None:
        top = Kit.write(tmp_path)
        included = Kit.write(tmp_path, "rule i { condition: true }", "inc.yar")
        before = MatchCache.identity([top, included], (), frozenset())
        included.write_text("rule i { condition: false }", encoding="utf-8")
        assert MatchCache.identity([top, included], (), frozenset()) != before

    def test_module_data_is_part_of_the_identity(self, tmp_path: Path) -> None:
        top = Kit.write(tmp_path)
        report = tmp_path / "report.json"
        report.write_text("{}", encoding="utf-8")
        first = MatchCache.identity([top], (("cuckoo", str(report)),), frozenset({"cuckoo"}))
        report.write_text('{"network": {}}', encoding="utf-8")
        assert (
            MatchCache.identity([top], (("cuckoo", str(report)),), frozenset({"cuckoo"})) != first
        )

    @pytest.mark.parametrize("module", ["time", "console"])
    def test_rules_that_read_the_clock_or_log_are_never_kept(
        self, tmp_path: Path, module: str
    ) -> None:
        assert MatchCache.identity([Kit.write(tmp_path)], (), frozenset({module})) is None

    def test_a_tampered_entry_is_refused_and_counted(self, tmp_path: Path) -> None:
        cache = MatchCache(tmp_path / "m")
        ident = Kit.identity(Kit.write(tmp_path))
        cache.put(ident, b"data", [Match("r", [], {}, [(0, "$a", b"d")])])
        entry = cache._path(ident, b"data")
        raw = entry.read_bytes()
        entry.write_bytes(raw.replace(b'"r"', b'"z"'))
        assert cache.get(ident, b"data") is None
        assert cache.refused == 1

    def test_an_entry_others_could_write_is_refused(self, tmp_path: Path) -> None:
        cache = MatchCache(tmp_path / "m")
        ident = Kit.identity(Kit.write(tmp_path))
        cache.put(ident, b"data", [])
        cache._path(ident, b"data").chmod(0o666)  # world-writable: the refusal is what is tested
        assert cache.get(ident, b"data") is None

    def test_meta_values_keep_their_type(self, tmp_path: Path) -> None:
        cache = MatchCache(tmp_path / "m")
        ident = Kit.identity(Kit.write(tmp_path))
        match = Match(
            "r", ["t"], {"n": 1, "s": "x", "b": True, "raw": b"\x00\xff"}, [(5, "$", b"ab")]
        )
        cache.put(ident, b"data", [match])
        assert cache.get(ident, b"data") == [match]


class TestThroughTheEngine:
    def test_the_second_scan_of_the_same_bytes_is_not_matched_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.detect.binary.rule_files import RuleFileEngine
        from cordon_scanner.foundation.paths import StatePaths

        monkeypatch.setattr(
            StatePaths, "default_cache_dir", staticmethod(lambda: tmp_path / "cache")
        )
        rules = Kit.write(tmp_path, "rule r { strings: $a = /n[a-z]{2,40}e/ condition: $a }")
        engine = RuleFileEngine(str(rules))
        data = b"x" * 400_000 + b"needle"
        started = time.process_time()
        first = engine.match(data)
        cold = time.process_time() - started
        started = time.process_time()
        second = engine.match(data)
        warm = time.process_time() - started
        assert first == second and engine.matches.hits == 1
        assert warm < cold

    def test_no_cache_keeps_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.detect.binary.rule_files import RuleFileEngine
        from cordon_scanner.foundation.paths import StatePaths

        monkeypatch.setattr(
            StatePaths, "default_cache_dir", staticmethod(lambda: tmp_path / "cache")
        )
        engine = RuleFileEngine(str(Kit.write(tmp_path)), use_cache=False)
        engine.match(b"needle")
        engine.match(b"needle")
        assert engine.identity is None and engine.matches.hits == 0
        assert not (tmp_path / "cache" / "rule-matches").exists()
        assert not (tmp_path / "cache" / "rule-packs").exists()
