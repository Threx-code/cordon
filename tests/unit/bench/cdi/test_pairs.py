"""Release-pair facts and the change detectors (learning loop rows LL-2 and LL-23), on fact vectors only: no package and no sample is
read; every record below is hand-made in the shape of `facts` version 3."""

from __future__ import annotations

import hashlib
import json
import sys
from itertools import cycle
from typing import Any

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Distiller, Unit
from bench.cdi.pairs import PairFacts, PairTerms

from cordon_scanner.report.facts import FACTS_VERSION


class PairKit:
    @staticmethod
    def file(
        key: str,
        *,
        ext: str = "js",
        places: tuple[str, ...] = (),
        caps: tuple[str, ...] = (),
        hosts: tuple[str, ...] = (),
        domains: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        reached = bool(places)
        return {
            "key": key,
            "ext": ext,
            "places": list(places),
            "reached": reached,
            "reach": "placed" if reached else "unreached",
            "reach_depth": 0,
            "rules": {},
            "suppressed": {},
            "capabilities": list(caps),
            "unread": [],
            "hosts": list(hosts),
            "domains": list(domains),
        }

    @staticmethod
    def facts(
        files: list[dict[str, Any]],
        *,
        hooks: tuple[tuple[str, tuple[str, ...]], ...] = (),
        direct: int = 0,
        local: int = 0,
        extensions: dict[str, int] | None = None,
        version: str = FACTS_VERSION,
    ) -> dict[str, Any]:
        package: dict[str, Any] = {
            "rules": {},
            "hooks": [{"kind": kind, "programs": list(programs)} for kind, programs in hooks],
            "dependencies": {"total": direct + local, "direct": direct, "local": local},
        }
        if extensions is not None:
            package["extensions"] = extensions
        record = {"facts_version": version, "package": package, "files": files}
        record["digest"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
        return record

    @staticmethod
    def before() -> dict[str, Any]:
        """The last clean release: an import entry that egresses to one host, one postinstall hook, two direct dependencies."""
        return PairKit.facts(
            [
                PairKit.file(
                    "a" * 16,
                    places=("import_entry",),
                    caps=("egress",),
                    hosts=("h1",),
                    domains=("d1",),
                )
            ],
            hooks=(("postinstall", ("node",)),),
            direct=2,
        )

    @staticmethod
    def after_all_six() -> dict[str, Any]:
        """The next release: a new capability in an install entry and in a file nothing reaches, a new hook kind and program, a native
        file, a new host and domain, and a new dependency."""
        return PairKit.facts(
            [
                PairKit.file(
                    "a" * 16,
                    places=("import_entry",),
                    caps=("egress",),
                    hosts=("h1", "h2"),
                    domains=("d1", "d2"),
                ),
                PairKit.file("b" * 16, places=("install_entry",), caps=("spawn", "egress")),
                PairKit.file("c" * 16, ext="node", caps=("write_file",)),
            ],
            hooks=(("postinstall", ("node",)), ("preinstall", ("curl", "sh"))),
            direct=3,
        )


class TestThePairNamesTheSixChanges:
    """LL-2: a fixture version pair names each of the six changes."""

    def pair(self) -> dict[str, Any]:
        return PairFacts.of(
            PairKit.before(),
            PairKit.after_all_six(),
            previous_is_clean=True,
            publisher_changed=True,
        )

    def test_a_new_capability_in_a_place_that_runs(self) -> None:
        assert ["install_entry", "egress", "spawn"] in self.pair()["new_capabilities"]
        assert all(
            entry[0] != "import_entry" for entry in self.pair()["new_capabilities"]
        )  # the import entry's egress is not new

    def test_a_new_capability_in_a_file_nothing_reaches(self) -> None:
        assert self.pair()["new_unreached_capabilities"] == [["unreached", "write_file"]]

    def test_a_new_hook_kind_and_the_programs_it_runs(self) -> None:
        pair = self.pair()
        assert pair["new_hook_kinds"] == ["preinstall"]
        assert pair["new_hook_programs"] == ["curl", "sh"]

    def test_a_new_native_file(self) -> None:
        assert self.pair()["new_binary_files"] == 1

    def test_a_new_host_and_domain_by_digest(self) -> None:
        pair = self.pair()
        assert (pair["new_hosts"], pair["new_domains"]) == (1, 1)

    def test_a_new_dependency(self) -> None:
        assert self.pair()["new_direct_dependencies"] == 1
        assert self.pair()["new_local_dependencies"] == 0

    def test_a_publisher_the_caller_names_as_changed(self) -> None:
        assert self.pair()["publisher_changed"] is True
        assert (
            PairFacts.of(PairKit.before(), PairKit.after_all_six(), previous_is_clean=True)[
                "publisher_changed"
            ]
            is False
        )


class TestOnlyWhatIsNewIsAChange:
    def test_the_same_release_against_itself_changes_nothing(self) -> None:
        pair = PairFacts.of(PairKit.before(), PairKit.before(), previous_is_clean=True)
        assert pair["new_capabilities"] == pair["new_unreached_capabilities"] == []
        assert (pair["new_hook_kinds"], pair["new_hook_programs"]) == ([], [])
        assert (
            pair["new_binary_files"],
            pair["new_hosts"],
            pair["new_domains"],
            pair["new_direct_dependencies"],
        ) == (0, 0, 0, 0)
        assert PairTerms.of(pair) == set()

    def test_a_removal_is_not_a_change(self) -> None:
        pair = PairFacts.of(PairKit.after_all_six(), PairKit.before(), previous_is_clean=True)
        assert pair["new_capabilities"] == pair["new_unreached_capabilities"] == []
        assert (
            pair["new_hook_kinds"],
            pair["new_binary_files"],
            pair["new_hosts"],
            pair["new_direct_dependencies"],
        ) == ([], 0, 0, 0)

    def test_the_order_of_files_and_hooks_does_not_matter(self) -> None:
        after = PairKit.after_all_six()
        shuffled = PairKit.facts(
            list(reversed(after["files"])),
            hooks=(("preinstall", ("curl", "sh")), ("postinstall", ("node",))),
            direct=3,
        )
        assert (
            PairFacts.of(PairKit.before(), after, previous_is_clean=True)["new_capabilities"]
            == PairFacts.of(PairKit.before(), shuffled, previous_is_clean=True)["new_capabilities"]
        )

    def test_the_same_pair_gives_the_same_record_and_digest(self) -> None:
        first = PairFacts.of(PairKit.before(), PairKit.after_all_six(), previous_is_clean=True)
        second = PairFacts.of(PairKit.before(), PairKit.after_all_six(), previous_is_clean=True)
        assert first == second
        assert len(first["digest"]) == 64


class TestThePreviousReleaseMustBeTheLastCleanOne:
    def test_a_pair_not_declared_clean_is_refused(self) -> None:
        with pytest.raises(ValueError, match="last clean release"):
            PairFacts.of(PairKit.before(), PairKit.after_all_six(), previous_is_clean=False)

    def test_records_of_two_facts_versions_are_refused(self) -> None:
        with pytest.raises(ValueError, match="different facts versions"):
            PairFacts.of(
                PairKit.facts([], version="2"),
                PairKit.facts([], version="3"),
                previous_is_clean=True,
            )

    def test_a_record_with_no_facts_version_is_refused(self) -> None:
        bare = {"files": [], "package": {}}
        with pytest.raises(ValueError, match="different facts versions"):
            PairFacts.of(bare, bare, previous_is_clean=True)


class TestNativeFiles:
    def test_a_known_native_file_is_not_new(self) -> None:
        native = PairKit.file("c" * 16, ext="node", caps=("write_file",))
        previous, current = (
            PairKit.facts([native]),
            PairKit.facts([native, PairKit.file("d" * 16, ext="so", caps=("spawn",))]),
        )
        assert PairFacts.of(previous, current, previous_is_clean=True)["new_binary_files"] == 1

    def test_a_source_file_is_not_native(self) -> None:
        current = PairKit.facts(
            [
                PairKit.file("d" * 16, ext="js", caps=("spawn",)),
                PairKit.file("e" * 16, ext="json", caps=("env",)),
            ]
        )
        assert (
            PairFacts.of(PairKit.facts([]), current, previous_is_clean=True)["new_binary_files"]
            == 0
        )

    def test_the_extension_counts_see_a_quiet_binary_the_file_entries_cannot(self) -> None:
        # A file with no capability, no finding and no unread state is not in the file entries; the counts are.
        previous = PairKit.facts([], extensions={"js": 10, "node": 0})
        current = PairKit.facts([], extensions={"js": 10, "node": 2, "so": 1})
        assert PairFacts.of(previous, current, previous_is_clean=True)["new_binary_files"] == 3

    def test_the_counts_are_used_only_when_both_records_have_them(self) -> None:
        previous = PairKit.facts([])
        current = PairKit.facts(
            [PairKit.file("d" * 16, ext="so", caps=("spawn",))], extensions={"so": 1}
        )
        assert PairFacts.of(previous, current, previous_is_clean=True)["new_binary_files"] == 1


class TestTheRecordHoldsNoName:
    def test_only_the_closed_set_of_fields_is_written(self) -> None:
        pair = PairFacts.of(PairKit.before(), PairKit.after_all_six(), previous_is_clean=True)
        assert sorted(pair) == [
            "current", "digest", "facts_version", "new_binary_files", "new_capabilities", "new_direct_dependencies",
            "new_domains", "new_hook_kinds", "new_hook_programs", "new_hosts", "new_local_dependencies",
            "new_unreached_capabilities", "pair_version", "previous", "publisher_changed",
        ]  # fmt: skip

    def test_a_host_digest_is_counted_never_copied(self) -> None:
        text = json.dumps(
            PairFacts.of(PairKit.before(), PairKit.after_all_six(), previous_is_clean=True)
        )
        assert '"h2"' not in text
        assert '"d2"' not in text


class TestPairTerms:
    def test_each_change_is_a_term_of_the_scanners_vocabulary(self) -> None:
        pair = PairFacts.of(
            PairKit.before(),
            PairKit.after_all_six(),
            previous_is_clean=True,
            publisher_changed=True,
        )
        terms = PairTerms.of(pair)
        assert ("change", "capability", "install_entry", "egress", "spawn") in terms
        assert ("change", "capability", "unreached", "write_file") in terms
        assert ("change", "hook", "preinstall") in terms
        assert ("change", "hook_program", "curl") in terms
        assert {
            ("change", "binary"),
            ("change", "host"),
            ("change", "domain"),
            ("change", "dependency"),
        } <= terms

    def test_the_publisher_flag_is_withheld_until_the_lead_decides(self) -> None:
        pair = PairFacts.of(
            PairKit.before(),
            PairKit.after_all_six(),
            previous_is_clean=True,
            publisher_changed=True,
        )
        assert ("change", "publisher") not in PairTerms.of(pair)
        assert pair["publisher_changed"] is True  # the record keeps it

    def test_no_term_is_of_a_kind_the_distiller_refuses(self) -> None:
        from bench.cdi.distill import REFUSED_KINDS

        pair = PairFacts.of(
            PairKit.before(),
            PairKit.after_all_six(),
            previous_is_clean=True,
            publisher_changed=True,
        )
        assert not {t[0] for t in PairTerms.of(pair)} & REFUSED_KINDS


class TestAChangeDetectorIsLearnedFromPairs:
    """LL-23: a fixture pair with a new capability in a place that runs yields a candidate."""

    @staticmethod
    def legit_pairs() -> list[dict[str, Any]]:
        """What ordinary updates do: nothing, a new reached helper, a new dependency."""
        base = PairKit.before()
        nothing = PairKit.before()
        helper = PairKit.facts(
            [*base["files"], PairKit.file("f" * 16, places=("import_entry",), caps=("read_file",))],
            hooks=(("postinstall", ("node",)),),
            direct=2,
        )
        dependency = PairKit.facts(base["files"], hooks=(("postinstall", ("node",)),), direct=3)
        return [
            PairFacts.of(base, after, previous_is_clean=True)
            for after in (nothing, helper, dependency)
        ]

    @staticmethod
    def poisoned_pair() -> dict[str, Any]:
        after = PairKit.facts(
            [
                *PairKit.before()["files"],
                PairKit.file("b" * 16, places=("install_entry",), caps=("spawn", "egress")),
            ],
            hooks=(("postinstall", ("node",)),),
            direct=2,
        )
        return PairFacts.of(PairKit.before(), after, previous_is_clean=True)

    @staticmethod
    def units(
        legit: list[dict[str, Any]],
        malicious: dict[str, Any],
        *,
        families: int,
        per: int,
        split: str = "train",
    ) -> list[Unit]:
        out = [
            Unit(f"{split}-legit-{i}", "legit", "", "npm", f"s{i % 3}", split, record)
            for i, record in zip(
                range(12_000 if split == "train" else 9_000), cycle(legit), strict=False
            )
        ]
        out += [
            Unit(f"{split}-mal-{f}-{j}", "mal", f"fam{f}", "npm", "s0", split, malicious)
            for f in range(families)
            for j in range(per)
        ]
        return out

    def distiller(self) -> Distiller:
        return Distiller(terms_of=PairTerms.of, generator="G6", metadata_kinds=frozenset())

    def test_a_new_capability_in_a_place_that_runs_is_a_candidate(self) -> None:
        legit, bad = self.legit_pairs(), self.poisoned_pair()
        units = self.units(legit, bad, families=4, per=3) + self.units(
            legit, bad, families=2, per=2, split="confirm"
        )
        run = self.distiller().distill(units)
        assert run.candidate is not None
        assert run.candidate["generator"] == "G6"
        assert any(
            term[:3] == ["change", "capability", "install_entry"]
            for term in run.candidate["predicate"]
        )

    def test_the_candidate_is_made_of_changes_only(self) -> None:
        legit, bad = self.legit_pairs(), self.poisoned_pair()
        units = self.units(legit, bad, families=4, per=3) + self.units(
            legit, bad, families=2, per=2, split="confirm"
        )
        run = self.distiller().distill(units)
        assert run.candidate is not None
        assert all(term[0] == "change" for term in run.candidate["predicate"])

    def test_a_change_ordinary_updates_make_is_not_a_candidate(self) -> None:
        legit = self.legit_pairs()
        helper_only = legit[1]  # the same change a third of legit updates make
        units = self.units(legit, helper_only, families=4, per=3) + self.units(
            legit, helper_only, families=2, per=2, split="confirm"
        )
        assert self.distiller().distill(units).candidate is None

    def test_one_family_alone_is_not_a_candidate(self) -> None:
        legit, bad = self.legit_pairs(), self.poisoned_pair()
        units = self.units(legit, bad, families=1, per=12) + self.units(
            legit, bad, families=1, per=3, split="confirm"
        )
        assert self.distiller().distill(units).candidate is None

    def test_the_default_distiller_is_unchanged_and_still_says_g2(self) -> None:
        run = Distiller().distill([])
        assert run.candidate is None
        assert Distiller().generator == "G2"


class TestWhatMutationFoundLoose:
    """The survivors of the first mutation run of `pairs.py`, each pinned: the digests a pair names, a local dependency counted apart, a record
    without dependencies, a fall in the extension counts, and a pair record with no field."""

    def test_the_pair_names_the_digests_of_both_records(self) -> None:
        before, after = PairKit.before(), PairKit.after_all_six()
        pair = PairFacts.of(before, after, previous_is_clean=True)
        assert (pair["previous"], pair["current"]) == (before["digest"], after["digest"])

    def test_a_new_local_dependency_is_counted_apart_from_a_direct_one(self) -> None:
        previous = PairKit.facts([], direct=2, local=0)
        current = PairKit.facts([], direct=2, local=1)
        pair = PairFacts.of(previous, current, previous_is_clean=True)
        assert (pair["new_direct_dependencies"], pair["new_local_dependencies"]) == (0, 1)

    def test_records_without_a_dependency_table_have_no_new_dependency(self) -> None:
        bare = {"facts_version": FACTS_VERSION, "package": {}, "files": []}
        pair = PairFacts.of(bare, bare, previous_is_clean=True)
        assert (pair["new_direct_dependencies"], pair["new_local_dependencies"]) == (0, 0)

    def test_a_fall_in_the_extension_counts_is_not_a_new_native_file(self) -> None:
        previous = PairKit.facts([], extensions={"node": 3, "so": 2})
        current = PairKit.facts([], extensions={"node": 1, "so": 2})
        assert PairFacts.of(previous, current, previous_is_clean=True)["new_binary_files"] == 0

    def test_a_pair_record_with_no_field_has_no_term(self) -> None:
        assert PairTerms.of({}) == set()

    def test_a_new_direct_and_a_new_local_dependency_make_one_dependency_term(self) -> None:
        pair = {"new_direct_dependencies": 1, "new_local_dependencies": 1}
        assert PairTerms.of(pair) == {("change", "dependency")}


class TestWhatMutationLeftLooseInThePairs:
    def test_a_record_with_no_dependency_table_against_one_with_a_direct_dependency(self) -> None:
        bare = {"facts_version": FACTS_VERSION, "package": {}, "files": []}
        current = PairKit.facts([], direct=1)
        pair = PairFacts.of(bare, current, previous_is_clean=True)
        assert pair["new_direct_dependencies"] == 1

    def test_a_new_local_dependency_alone_is_a_dependency_term(self) -> None:
        assert PairTerms.of({"new_direct_dependencies": 0, "new_local_dependencies": 1}) == {
            ("change", "dependency")
        }

    def test_the_publisher_term_comes_back_when_the_withheld_set_is_emptied(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(PairTerms, "WITHHELD", frozenset())
        assert ("change", "publisher") in PairTerms.of({"publisher_changed": True})
        assert ("change", "publisher") not in PairTerms.of({"publisher_changed": False})
        assert ("change", "publisher") not in PairTerms.of({})
