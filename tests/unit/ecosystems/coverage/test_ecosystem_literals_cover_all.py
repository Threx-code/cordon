"""S22, structurally: no list of ecosystems in the source may be narrower than the scanner's 28, and none may be added.

The syntax tree of `src/` is read (`kits/ecosystem_literals.py`): every set, tuple, list or dict literal whose string members name two or
more ecosystems is a site. A site that names all 28 is complete. Today's narrow sites are listed in `narrow_sites.json`, each with the ids it
names; the list may only SHRINK:

* a narrow site that is not in the list fails at once (widen it to all 28, or make it not a list of ecosystems);
* a listed site may gain ids, never lose them;
* a listed site that has become complete, or is gone, fails until its entry is removed.

A site is identified by its file, the name it is assigned to (or the function that holds it) and its number among that anchor's sites, so
an edit elsewhere in the file does not move it."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from kits.ecosystem_literals import ALL, EcosystemLiterals
from support import ROOT

RECORD = ROOT / "tests" / "unit" / "ecosystems" / "coverage" / "narrow_sites.json"


class Recorded:
    @staticmethod
    def reasons() -> dict[str, str]:
        """Sites narrow by nature, each with its written reason (the only way off the record besides widening)."""
        rows = json.loads(RECORD.read_text(encoding="utf-8"))
        return {row["site"]: row["reason"] for row in rows if "reason" in row}

    @staticmethod
    def entries() -> dict[str, frozenset[str]]:
        rows = json.loads(RECORD.read_text(encoding="utf-8"))
        keys = [row["site"] for row in rows]
        assert len(keys) == len(set(keys)), "a site is listed twice"
        return {row["site"]: frozenset(row["ids"]) for row in rows}

    @staticmethod
    def found() -> dict[str, frozenset[str]]:
        return {site.key: site.ids for site in EcosystemLiterals.narrow(ROOT / "src", ROOT)}


class TestNoNarrowListOfEcosystemsIsAdded:
    def test_every_narrow_site_in_the_source_is_one_the_record_already_holds(self) -> None:
        listed = Recorded.entries()
        new = sorted(set(Recorded.found()) - set(listed))
        assert not new, (
            f"{len(new)} narrow list(s) of ecosystems that are not on the record: widen each to all {len(ALL)}, or stop it listing ecosystems: {new}"
        )

    def test_a_listed_site_never_loses_an_ecosystem(self) -> None:
        listed, found = Recorded.entries(), Recorded.found()
        lost = {
            key: sorted(listed[key] - found[key])
            for key in listed
            if key in found and not listed[key] <= found[key]
        }
        assert not lost, f"sites that now name fewer ecosystems than the record: {lost}"


class TestTheRecordOnlyShrinks:
    def test_a_listed_site_that_is_complete_or_gone_is_taken_off_the_record(self) -> None:
        stale = sorted(set(Recorded.entries()) - set(Recorded.found()))
        assert not stale, (
            f"remove from narrow_sites.json (the site covers all {len(ALL)} or no longer exists): {stale}"
        )

    def test_the_record_names_real_ecosystems(self) -> None:
        for key, ids in Recorded.entries().items():
            assert ids and ids <= ALL, key

    def test_a_site_narrow_by_nature_has_a_written_reason_that_says_something(self) -> None:
        for key, why in Recorded.reasons().items():
            assert len(why) >= 60 and why.endswith("."), key


class TestTheScannerOfTheSource:
    @staticmethod
    def sites(tmp_path: Path, text: str) -> list:
        (tmp_path / "m.py").write_text(text, encoding="utf-8")
        return EcosystemLiterals.sites(tmp_path, tmp_path)

    def test_a_set_naming_two_ecosystems_is_a_narrow_site(self, tmp_path: Path) -> None:
        found = self.sites(tmp_path, 'COVERED = frozenset({"npm", "pypi"})\n')
        assert [(s.key, s.complete) for s in found] == [("m.py::COVERED#0", False)]

    def test_a_list_of_all_the_ecosystems_is_complete(self, tmp_path: Path) -> None:
        names = ", ".join(f'"{eco}"' for eco in sorted(ALL))
        found = self.sites(tmp_path, f"EVERY = ({names})\n")
        assert [s.complete for s in found] == [True]

    def test_one_ecosystem_among_other_words_is_not_a_site(self, tmp_path: Path) -> None:
        assert self.sites(tmp_path, 'KINDS = ("image", "video", "audio", "text")\n') == []

    def test_a_package_url_type_counts_as_the_ecosystem_it_names(self, tmp_path: Path) -> None:
        found = self.sites(tmp_path, 'TYPES = {"gem": 1, "golang": 2}\n')
        assert [sorted(s.ids) for s in found] == [["gomod", "rubygems"]]

    def test_an_id_the_registry_folds_into_another_still_names_itself(self, tmp_path: Path) -> None:
        found = self.sites(tmp_path, 'FAMILY = {"gradle", "maven"}\n')
        assert [sorted(s.ids) for s in found] == [["gradle", "maven"]]

    def test_a_site_inside_a_function_is_anchored_by_the_function(self, tmp_path: Path) -> None:
        found = self.sites(tmp_path, 'def pick(x):\n    return x in ("npm", "pypi")\n')
        assert [s.key for s in found] == ["m.py::pick#0"]

    def test_the_identity_does_not_move_with_the_line(self, tmp_path: Path) -> None:
        before = self.sites(tmp_path, 'A = {"npm", "pypi"}\n')
        after = self.sites(
            tmp_path, '"""a longer module docstring\n\nof several lines"""\n\nA = {"npm", "pypi"}\n'
        )
        assert before[0].key == after[0].key and before[0].line != after[0].line

    def test_two_sites_in_one_function_are_numbered(self, tmp_path: Path) -> None:
        text = 'def f(x):\n    a = ("npm", "pypi")\n    return x in ("cargo", "gomod")\n'
        assert sorted(s.key for s in self.sites(tmp_path, text)) == ["m.py::a#0", "m.py::f#0"]

    @pytest.mark.parametrize("text", ['X = ("npm",)\n', "X = ()\n", 'X = [1, 2, "npm"]\n'])
    def test_fewer_than_two_ecosystems_is_not_a_site(self, tmp_path: Path, text: str) -> None:
        assert self.sites(tmp_path, text) == []

    def test_the_scan_reads_syntax_only(self, tmp_path: Path) -> None:
        (tmp_path / "m.py").write_text('import os\nX = {"npm", "pypi"}\n', encoding="utf-8")
        assert (
            ast.parse((tmp_path / "m.py").read_text())
            and len(EcosystemLiterals.sites(tmp_path, tmp_path)) == 1
        )
