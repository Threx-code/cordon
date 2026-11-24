"""Facts are kept under the unit's digest, the reader's version and the terms' version, so a head that changes one reader makes only that reader's facts again."""

from __future__ import annotations

from bench.cdi.factstore import FactStore, Reader

UNITS = {f"unit-{n}": f"some hook text {n} hook".encode() for n in range(5)}


class Kit:
    @staticmethod
    def readers(**versions: str) -> list[Reader]:
        return [
            Reader("flows", versions.get("flows", "1"), lambda data: {"flows": len(data)}),
            Reader(
                "hooks", versions.get("hooks", "1"), lambda data: {"hooks": data.count(b"hook")}
            ),
            Reader("words", versions.get("words", "1"), lambda data: {"words": len(data.split())}),
        ]

    @staticmethod
    def run(store: FactStore) -> None:
        for digest, content in UNITS.items():
            store.facts(digest, content)


class TestFactsAreKeptByWhatMadeThem:
    def test_every_reader_reads_every_unit_once(self) -> None:
        store = FactStore(Kit.readers(), "1")
        Kit.run(store)
        Kit.run(store)
        assert len(store.made) == 15

    def test_the_facts_are_what_the_readers_returned(self) -> None:
        store = FactStore(Kit.readers(), "1")
        facts = store.facts("unit-0", UNITS["unit-0"])
        assert facts == {"flows": {"flows": 21}, "hooks": {"hooks": 2}, "words": {"words": 5}}

    def test_a_head_that_changes_one_reader_makes_only_that_readers_facts_again(self) -> None:
        kept: dict[str, str] = {}
        Kit.run(FactStore(Kit.readers(), "1", kept))
        head = FactStore(Kit.readers(hooks="2"), "1", kept)
        Kit.run(head)
        assert sorted(reader for _, reader in head.made) == ["hooks"] * 5
        assert len(head.made) == 5

    def test_a_head_that_changes_nothing_makes_nothing(self) -> None:
        kept: dict[str, str] = {}
        Kit.run(FactStore(Kit.readers(), "1", kept))
        again = FactStore(Kit.readers(), "1", kept)
        Kit.run(again)
        assert again.made == []

    def test_a_change_of_the_term_version_makes_every_reader_again(self) -> None:
        kept: dict[str, str] = {}
        Kit.run(FactStore(Kit.readers(), "1", kept))
        moved = FactStore(Kit.readers(), "2", kept)
        Kit.run(moved)
        assert len(moved.made) == 15

    def test_a_unit_with_other_content_is_another_key(self) -> None:
        store = FactStore(Kit.readers(), "1")
        store.facts("unit-0", b"a")
        store.facts("unit-1", b"a")
        assert len(store.made) == 6


class TestACandidateReadingANewFactIsRefused:
    def test_a_fact_the_store_has_is_admitted(self) -> None:
        store = FactStore(Kit.readers(), "1")
        assert store.refuses({"flows", "hooks"}, "1") is None

    def test_a_fact_no_reader_of_the_store_makes_is_refused_and_named(self) -> None:
        reason = FactStore(Kit.readers(), "1").refuses({"flows", "environment_gate"}, "1")
        assert reason is not None and "environment_gate" in reason and "rebuild" in reason

    def test_terms_of_another_version_are_refused(self) -> None:
        reason = FactStore(Kit.readers(), "1").refuses({"flows"}, "2")
        assert reason is not None and "version 2" in reason
