"""engine.isolation.facts (item 56, phase (a)): per-file facts cross from a worker to the parent as
plain data only, bounded per file and per scan, each kind checked against its declared shape; refused,
the file is a gap at its path and none of its facts are used. The parent parses no scanned content:
the facts are how it learns, across files, what only a worker may read."""

from __future__ import annotations

import json

import pytest

from cordon_scanner import Config, Scanner
from cordon_scanner.detect.base import DetectorRequirements, ScanContext
from cordon_scanner.engine.isolation import facts as channel
from cordon_scanner.engine.isolation.facts import FILE_BYTES, FILE_COUNT, Facts, WorkerFacts
from cordon_scanner.foundation.models import Category


class Sends:
    """A detector given to the Scanner that sends facts from its worker, by the file's name."""

    id = "planted-facts"
    version = "1.0.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit, ctx):
        name = unit.path.rsplit("/", 1)[-1]
        if name == "good.py":
            WorkerFacts.add("python.import", ["os.path", 0, 1, "module"])
            WorkerFacts.add("python.dotted_path", "pkg.good")
        elif name == "shape.py":
            WorkerFacts.add("python.import", ["os", "zero", 1, "module"])
        elif name == "object.py":
            WorkerFacts.add("python.dotted_path", object())
        elif name == "many.py":
            for i in range(FILE_COUNT + 5):
                WorkerFacts.add("python.dotted_path", f"m{i}")
        return ()


class FactsKit:
    @staticmethod
    def scan(tmp_path, names, monkeypatch):
        """Scan files named `names` with the planted detector; what the parent was handed and accepted."""
        from cordon_scanner.engine.registry import Registry

        root = tmp_path / "tree"
        root.mkdir()
        for name in names:
            (root / name).write_text(f"# plain text of {name}\n", encoding="utf-8")
        handed: list[int] = []
        real = Facts.accept

        def accept(text, spent):
            handed.append(len(text))
            return real(text, spent)

        monkeypatch.setattr(Facts, "accept", staticmethod(accept))
        config = Config.default().with_overrides(use_cache=False, offline=True)
        result = Scanner(config, detectors=(*Registry.default_detectors(), Sends())).scan(root)
        return result, handed

    @staticmethod
    def refused(result) -> dict[str, str]:
        return {
            f.location.path: f.message
            for f in result.findings
            if f.rule_id == "OPERATIONAL.WORKER.FACTS_REFUSED"
        }


class TestThePlainDataRule:
    def test_a_declared_fact_is_accepted(self) -> None:
        text = json.dumps({"python.import": [["os", 0, 3, "function"]], "js.require": ["dynamic"]})
        assert Facts.accept(text, 0) == (
            {"python.import": [["os", 0, 3, "function"]], "js.require": ["dynamic"]},
            "",
        )

    @pytest.mark.parametrize(
        "decoded",
        [
            {"python.import": [["os", "0", 3, "module"]]},  # a level that is not an int
            {"python.import": [["os", 0, 3, "everywhere"]]},  # an undeclared scope
            {"python.import": [["os", True, 3, "module"]]},  # a bool is not a level
            {"python.dotted_path": [""]},
            {"shell.command": ["rm"]},  # an undeclared kind
            {"python.import": "os"},  # not a list
        ],
        ids=["level-str", "scope", "level-bool", "empty", "kind", "not-a-list"],
    )
    def test_a_fact_off_its_shape_is_refused(self, decoded) -> None:
        accepted, why = Facts.accept(json.dumps(decoded), 0)
        assert accepted is None and why

    def test_a_non_plain_value_never_crosses(self) -> None:
        WorkerFacts.begin()
        WorkerFacts.add("python.dotted_path", object())
        assert Facts.accept(WorkerFacts.end(), 0)[0] is None

    def test_past_its_bounds_a_set_is_refused_before_it_is_decoded(self, monkeypatch) -> None:
        def no_decode(*_args, **_kwargs):
            raise AssertionError("an oversized payload was decoded")

        monkeypatch.setattr(channel.json, "loads", no_decode)
        assert Facts.accept("x" * (FILE_BYTES + 1), 0)[0] is None
        assert Facts.accept('{"python.dotted_path":["a"]}', channel.SCAN_BYTES)[0] is None

    def test_the_worker_bounds_the_count_before_anything_crosses(self) -> None:
        WorkerFacts.begin()
        for i in range(FILE_COUNT + 1):
            WorkerFacts.add("python.dotted_path", f"m{i}")
        text = WorkerFacts.end()
        assert len(text) < 64 and Facts.accept(text, 0)[0] is None

    def test_outside_a_unit_nothing_is_gathered(self) -> None:
        WorkerFacts.add("python.dotted_path", "pkg.parent")  # the parent: no unit, no sink
        WorkerFacts.begin()
        assert WorkerFacts.end() == ""


class TestThroughTheWorkers:
    def test_a_worker_s_facts_reach_the_parent_and_bad_ones_are_gaps(
        self, tmp_path, monkeypatch
    ) -> None:
        result, handed = FactsKit.scan(
            tmp_path, ["good.py", "shape.py", "object.py", "many.py", "none.py"], monkeypatch
        )
        refused = FactsKit.refused(result)
        assert set(refused) == {"shape.py", "object.py", "many.py"}, refused
        assert not result.content_complete
        # the inflated set crossed as a marker: the parent never held FILE_COUNT facts
        assert handed and max(handed) < 256, handed

    def test_a_scan_with_none_is_unchanged(self, tmp_path, monkeypatch) -> None:
        result, handed = FactsKit.scan(tmp_path, ["none.py", "other.py"], monkeypatch)
        assert handed == [] and not FactsKit.refused(result)
        assert result.content_complete
