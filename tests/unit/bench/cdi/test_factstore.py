"""Facts are kept under the unit's digest, the reader's version and the terms' version, so a head that changes one reader makes only that reader's facts again."""

from __future__ import annotations

from bench.cdi.factstore import FactStore, Reader


def readers(**versions: str) -> list[Reader]:
    return [
        Reader("flows", versions.get("flows", "1"), lambda data: {"flows": len(data)}),
        Reader("hooks", versions.get("hooks", "1"), lambda data: {"hooks": data.count(b"hook")}),
        Reader("words", versions.get("words", "1"), lambda data: {"words": len(data.split())}),
    ]


UNITS = {f"unit-{n}": f"some hook text {n} hook".encode() for n in range(5)}


def run(store: FactStore) -> None:
    for digest, content in UNITS.items():
        store.facts(digest, content)


class TestFactsAreKeptByWhatMadeThem:
    def test_every_reader_reads_every_unit_once(self) -> None:
        store = FactStore(readers(), "1")
        run(store)
        run(store)
        assert len(store.made) == 15

    def test_the_facts_are_what_the_readers_returned(self) -> None:
        store = FactStore(readers(), "1")
        facts = store.facts("unit-0", UNITS["unit-0"])
        assert facts == {"flows": {"flows": 21}, "hooks": {"hooks": 2}, "words": {"words": 5}}

    def test_a_head_that_changes_one_reader_makes_only_that_readers_facts_again(self) -> None:
        kept: dict[str, str] = {}
        run(FactStore(readers(), "1", kept))
        head = FactStore(readers(hooks="2"), "1", kept)
        run(head)
        assert sorted(reader for _, reader in head.made) == ["hooks"] * 5
        assert len(head.made) == 5

    def test_a_head_that_changes_nothing_makes_nothing(self) -> None:
        kept: dict[str, str] = {}
        run(FactStore(readers(), "1", kept))
        again = FactStore(readers(), "1", kept)
        run(again)
        assert again.made == []

    def test_a_change_of_the_term_version_makes_every_reader_again(self) -> None:
        kept: dict[str, str] = {}
        run(FactStore(readers(), "1", kept))
        moved = FactStore(readers(), "2", kept)
        run(moved)
        assert len(moved.made) == 15

    def test_a_unit_with_other_content_is_another_key(self) -> None:
        store = FactStore(readers(), "1")
        store.facts("unit-0", b"a")
        store.facts("unit-1", b"a")
        assert len(store.made) == 6
