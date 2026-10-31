"""The compiled-pack cache (rule_engine/pack_cache): a kept compile matches as a fresh one, and an
entry is refused whenever what made it changed, or anyone but this user could have written it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.pack_cache import PackCache
from cordon_scanner.detect.binary.rule_engine.tokens import Includes

RULES = 'rule a { strings: $x = "EVIL" condition: $x } rule b { condition: filesize > 3 }'


class Kept:
    """The one entry a cache directory holds."""

    @staticmethod
    def entry(root: Path) -> Path:
        (only,) = [p for p in root.iterdir() if not p.name.startswith(".")]
        return only


class TestThePackCache:
    def test_a_kept_compile_matches_as_a_fresh_one(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        first = Rules.compile(RULES, cache=cache)
        second = Rules.compile(RULES, cache=cache)
        assert cache.loaded == 1
        data = b"xxEVILxx"
        assert [(m.rule, m.strings) for m in second.match(data)] == [
            (m.rule, m.strings) for m in first.match(data)
        ]

    def test_other_text_or_externals_are_another_entry(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        Rules.compile(RULES + " rule c { condition: true }", cache=cache)
        Rules.compile(RULES, externals={"x": 1}, cache=cache)
        assert cache.loaded == 0

    def test_an_entry_others_could_write_is_refused(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        Kept.entry(tmp_path).chmod(0o666)
        Rules.compile(RULES, cache=cache)
        assert (cache.loaded, cache.refused) == (0, 1)

    def test_a_changed_included_file_is_a_miss(self, tmp_path: Path) -> None:
        (tmp_path / "m.yar").write_text("rule m { condition: true }", encoding="utf-8")
        cache = PackCache(tmp_path / "cache")
        text = 'include "m.yar"'
        Rules.compile(text, includes=Includes(tmp_path), cache=cache)
        Rules.compile(text, includes=Includes(tmp_path), cache=cache)
        assert cache.loaded == 1
        (tmp_path / "m.yar").write_text("rule m { condition: false }", encoding="utf-8")
        rules = Rules.compile(text, includes=Includes(tmp_path), cache=cache)
        assert cache.loaded == 1
        assert not rules.match(b"x")

    def test_this_build_is_named(self, tmp_path: Path) -> None:
        engine, build, abi = PackCache(tmp_path).made_by.split(" ")
        assert (len(engine), build) == (16, "python")
        assert abi.startswith("cpython-")

    @pytest.mark.parametrize(
        "other",
        [
            "0123456789abcdef compiled:0123456789abcdef cpython-312-aarch64",  # another build
            "another-engine python cpython-312-aarch64",  # another engine
        ],
    )
    def test_an_entry_another_maker_kept_is_never_read(self, tmp_path: Path, other: str) -> None:
        """An interpreted build's entry is never unpickled by a compiled build, or the other way,
        nor by another engine."""
        Rules.compile(RULES, cache=PackCache(tmp_path, made_by=other))
        cache = PackCache(tmp_path)
        assert Rules.compile(RULES, cache=cache).match(b"EVIL")
        assert cache.loaded == 0
        assert len([p for p in tmp_path.iterdir() if not p.name.startswith(".")]) == 2  # one each

    def test_an_entry_renamed_to_another_makers_key_is_refused(self, tmp_path: Path) -> None:
        """The signed header names the maker too, so the key alone is not trusted."""
        other = "another-engine python cpython-312-aarch64"
        Rules.compile(RULES, cache=PackCache(tmp_path, made_by=other))
        cache = PackCache(tmp_path)
        Kept.entry(tmp_path).rename(tmp_path / cache.key(RULES, {}, frozenset(Rules.loaded(None))))
        assert Rules.compile(RULES, cache=cache).match(b"EVIL")
        assert cache.loaded == 0

    def test_a_corrupt_entry_is_a_miss(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        entry = Kept.entry(tmp_path)
        entry.write_bytes(entry.read_bytes()[:-20])
        assert Rules.compile(RULES, cache=cache).match(b"EVIL")
        assert cache.loaded == 0


class TestRulesKeptAreBuiltOnFirstRun:
    MIXED = (
        'private rule base { strings: $a = "AA" condition: $a } '
        "global rule g { condition: filesize > 2 } "
        'rule uses { strings: $b = "BB" condition: base and $b } '
        "rule loop { condition: for any i in (0 .. filesize - 1) : ( uint8(i) == 0x43 ) } "
        'rule set { strings: $c = "CC" $d = "DD" condition: 1 of ($c, $d) and uses }'
    )

    def test_a_kept_set_answers_as_a_fresh_one(self, tmp_path: Path) -> None:
        fresh = Rules.compile(self.MIXED)
        cache = PackCache(tmp_path)
        Rules.compile(self.MIXED, cache=cache)
        kept = Rules.compile(self.MIXED, cache=cache)
        for data in (b"AABBCC", b"AABB", b"BBCC", b"x", b"AACCDDBB", b"C"):
            assert [(m.rule, m.strings) for m in kept.match(data)] == [
                (m.rule, m.strings) for m in fresh.match(data)
            ]

    def test_a_set_that_does_not_build_is_never_kept(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        with pytest.raises(RuleError):
            Rules.compile('rule r { condition: "a" + 1 }', cache=cache)
        assert [p for p in tmp_path.iterdir() if not p.name.startswith(".")] == []


class TestTheSignature:
    def test_a_tampered_pickle_is_never_loaded(self, tmp_path: Path) -> None:
        import pickle

        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        entry = Kept.entry(tmp_path)
        mac, header, _ = entry.read_bytes().split(b"\n", 2)

        class Boom:
            def __reduce__(self) -> Any:
                return (pytest.fail, ("the tampered pickle was loaded",))

        entry.write_bytes(mac + b"\n" + header + b"\n" + pickle.dumps(Boom()))
        fresh = PackCache(tmp_path)
        assert Rules.compile(RULES, cache=fresh).match(b"EVIL")
        assert (fresh.loaded, fresh.refused) == (0, 1)

    def test_an_unsigned_entry_is_refused(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        entry = Kept.entry(tmp_path)
        entry.write_bytes(entry.read_bytes().split(b"\n", 1)[1])
        fresh = PackCache(tmp_path)
        Rules.compile(RULES, cache=fresh)
        assert fresh.refused == 1

    def test_a_key_others_can_read_is_replaced(self, tmp_path: Path) -> None:
        cache = PackCache(tmp_path)
        Rules.compile(RULES, cache=cache)
        key = tmp_path / PackCache.KEY_NAME
        key.chmod(0o644)
        fresh = PackCache(tmp_path)
        Rules.compile(RULES, cache=fresh)
        assert fresh.refused == 1
        assert not key.stat().st_mode & 0o077
