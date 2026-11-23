"""A fixed, hashed corpus of invented packages may not scan slower or with more memory than the recorded budget.

The corpus (`tests/kits/perf_corpus.py`) is generated from a fixed seed and its content hash is held here, so changing
the generator changes the hash and fails the first test. The p99 package scan time (read in units of a fixed pure-Python
workload, so it holds on any machine) and the traced peak memory are held to the budgets of `tests/unit/data/perf/baseline.json`,
which sit about 1.5 times above the worst of the measured runs: a regression of either fails the prepush run.
"""

from __future__ import annotations

import json
from pathlib import Path

from kits.perf_corpus import PerfCorpus
from support import ROOT

BASELINE = json.loads(
    (ROOT / "tests" / "unit" / "data" / "perf" / "baseline.json").read_text(encoding="utf-8")
)


class TestTheCorpusIsFixed:
    def test_its_content_hash_is_the_recorded_one(self) -> None:
        assert PerfCorpus.digest() == BASELINE["corpus_sha256"]

    def test_it_holds_the_shapes_that_cost_most(self) -> None:
        names = list(PerfCorpus.files())
        assert len(names) > 250
        assert any(n.endswith("min.js") for n in names) and any(
            n.endswith("nest.js") for n in names
        )


class TestNoRegression:
    def test_the_p99_scan_time_and_the_peak_memory_are_within_the_budget(
        self, tmp_path: Path
    ) -> None:
        measured = PerfCorpus.measure(tmp_path)
        assert measured["packages"] == PerfCorpus.PACKAGES
        assert measured["p99_ratio"] <= BASELINE["budget"]["p99_ratio"], measured
        assert measured["peak_kb"] <= BASELINE["budget"]["peak_kb"], measured

    def test_the_budget_is_above_every_recorded_run(self) -> None:
        for name, runs in BASELINE["measured"].items():
            assert max(runs) < BASELINE["budget"][name]
