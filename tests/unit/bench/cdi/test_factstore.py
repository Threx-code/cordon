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

    def test_the_pre_test_stops_a_refused_candidate_with_the_reason(self) -> None:
        from bench.cdi.pretest import PreTest

        store = FactStore(Kit.readers(), "1")
        out = PreTest.decide(
            "cdi.code.env_gate",
            "npm",
            families_caught=["a", "b", "c", "d"],
            own_family="z",
            legit_hits=0,
            legit_units=5000,
            milliseconds=1.0,
            budget_ms=10.0,
            store=store,
            reads={"flows", "environment_gate"},
            term_version="1",
        )
        assert out["decision"] == "refused" and "environment_gate" in out["reasons"][0]
        assert "legit" not in out

    def test_a_candidate_the_store_admits_is_decided_on_its_numbers(self) -> None:
        from bench.cdi.pretest import PreTest

        out = PreTest.decide(
            "cdi.x",
            "npm",
            families_caught=["a", "b", "c", "d"],
            own_family="z",
            legit_hits=0,
            legit_units=5000,
            milliseconds=1.0,
            budget_ms=10.0,
            store=FactStore(Kit.readers(), "1"),
            reads={"flows"},
            term_version="1",
        )
        assert out["decision"] == "proceed"


class TestTheLegitimateStoreIsRebuiltPerHead:
    """LL-104: a candidate reading a new fact against an old store is refused; the store is rebuilt at the candidate's head, reading only what changed."""

    @staticmethod
    def newer() -> list[Reader]:
        return [*Kit.readers(hooks="2"), Reader("urls", "1", lambda data: {"urls": data.count(b"http")})]

    def old(self) -> tuple[FactStore, dict[str, str]]:
        kept: dict[str, str] = {}
        store = FactStore(Kit.readers(), "1", kept, head="aaaa111")
        Kit.run(store)
        return store, kept

    def test_the_rebuild_makes_only_the_changed_and_the_new_readers_facts(self) -> None:
        old, _ = self.old()
        rebuilt, record = old.rebuild(UNITS, self.newer(), "1", "bbbb222")
        assert (record.units, record.made, record.kept) == (5, 10, 10)
        assert sorted({reader for _, reader in rebuilt.made}) == ["hooks", "urls"]
        assert record.readers == {"flows": "1", "hooks": "2", "words": "1", "urls": "1"} and record.head == "bbbb222"

    def test_the_old_store_refuses_a_candidate_that_reads_the_new_fact_and_the_rebuilt_one_admits_it(self) -> None:
        old, _ = self.old()
        rebuilt, _ = old.rebuild(UNITS, self.newer(), "1", "bbbb222")
        assert "urls" in (old.refuses({"urls"}, "1") or "")
        assert rebuilt.refuses({"urls", "hooks"}, "1") is None

    def test_a_candidate_of_another_head_is_refused_and_one_of_the_stores_head_is_not(self) -> None:
        old, _ = self.old()
        assert "head bbbb222" in (old.refuses({"flows"}, "1", "bbbb222") or "")
        assert old.refuses({"flows"}, "1", "aaaa111") is None
        assert old.refuses({"flows"}, "1") is None

    def test_a_unit_that_could_not_be_read_is_named_not_read_as_having_no_facts(self) -> None:
        old, _ = self.old()
        units = {**UNITS, "unit-x": None}
        rebuilt, record = old.rebuild(units, Kit.readers(), "1", "bbbb222")
        assert record.unread == ("unit-x",) and record.units == 6 and (record.made, record.kept) == (0, 15)
        assert all(digest != "unit-x" for digest, _ in rebuilt.made)

    def test_the_rebuild_leaves_the_old_store_as_it_was(self) -> None:
        old, kept = self.old()
        before = dict(kept)
        old.rebuild(UNITS, self.newer(), "1", "bbbb222")
        assert old.head == "aaaa111" and len(old.made) == 15
        assert all(kept[key] == value for key, value in before.items())

    def test_a_new_term_version_makes_every_fact_again(self) -> None:
        old, _ = self.old()
        _, record = old.rebuild(UNITS, Kit.readers(), "2", "bbbb222")
        assert (record.made, record.kept) == (15, 0)
