"""The compiled-pack cache (rule_engine/pack_cache): a kept compile matches as a fresh one, and an
entry is refused whenever what made it changed, or anyone but this user could have written it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_engine.lang import Rules
from cordon_scanner.detect.binary.rule_engine.pack_cache import PackCache
from cordon_scanner.detect.binary.rule_engine.tokens import Includes

RULES = 'rule a { strings: $x = "EVIL" condition: $x } rule b { condition: filesize > 3 }'


class Spy:
    """Counts reads of rule text, so a test sees whether the cache was used."""

    calls: int = 0

    @staticmethod
    def install(monkeypatch: pytest.MonkeyPatch) -> None:
        original = Rules._read
        Spy.calls = 0

        def counted(*args: Any, **kwargs: Any) -> Any:
            Spy.calls += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(Rules, "_read", staticmethod(counted))

    @staticmethod
    def entry(root: Path) -> Path:
        (only,) = [p for p in root.iterdir() if not p.name.startswith(".")]
        return only


class TestThePackCache:
    def test_a_kept_compile_matches_as_a_fresh_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Spy.install(monkeypatch)
        cache = PackCache(tmp_path)
        first = Rules.compile(RULES, cache=cache)
        second = Rules.compile(RULES, cache=cache)
        assert Spy.calls == 1
        data = b"xxEVILxx"
        assert [(m.rule, m.strings) for m in second.match(data)] == [
            (m.rule, m.strings) for m in first.match(data)
        ]

    def test_other_text_or_externals_are_another_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Spy.install(monkeypatch)
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        Rules.compile(RULES + " rule c { condition: true }", cache=cache)
        Rules.compile(RULES, externals={"x": 1}, cache=cache)
        assert Spy.calls == 3

    def test_an_entry_others_could_write_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Spy.install(monkeypatch)
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        Spy.entry(tmp_path).chmod(0o666)
        Rules.compile(RULES, cache=cache)
        assert Spy.calls == 2

    def test_a_changed_included_file_is_a_miss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Spy.install(monkeypatch)
        (tmp_path / "m.yar").write_text("rule m { condition: true }", encoding="utf-8")
        cache = PackCache(tmp_path / "cache")
        text = 'include "m.yar"'
        Rules.compile(text, includes=Includes(tmp_path), cache=cache)
        Rules.compile(text, includes=Includes(tmp_path), cache=cache)
        assert Spy.calls == 1
        (tmp_path / "m.yar").write_text("rule m { condition: false }", encoding="utf-8")
        rules = Rules.compile(text, includes=Includes(tmp_path), cache=cache)
        assert Spy.calls == 2
        assert not rules.match(b"x")

    def test_another_engine_never_reads_the_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Spy.install(monkeypatch)
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        monkeypatch.setattr(PackCache, "_ENGINE", "another-engine")
        Rules.compile(RULES, cache=cache)
        assert Spy.calls == 2

    def test_a_corrupt_entry_is_a_miss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Spy.install(monkeypatch)
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        entry = Spy.entry(tmp_path)
        entry.write_bytes(entry.read_bytes()[:-20])
        assert Rules.compile(RULES, cache=cache).match(b"EVIL")
        assert Spy.calls == 2
