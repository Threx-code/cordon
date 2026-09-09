"""No detector ships without ever running.

A detector that never fires is indistinguishable, in a report, from one that ran
and found nothing. That makes a dead detector the most expensive kind of bug
here: it looks exactly like coverage.

This test asserts every shipped detector produces at least one finding somewhere
in the corpus, with a short list of documented exceptions -- each of which needs
input the corpus cannot hold, and each of which is exercised by its own unit
tests instead. Adding a detector without a sample that proves it works fails
here rather than quietly adding a name to `cordon rules list`.

It found two things when it was written: four detectors that had never been
exercised by the corpus at all, and a VCS detector reporting files outside the
directory it was asked to scan.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.registry import Registry
from support import requires_malicious_corpus

CORPUS = Path(__file__).resolve().parents[2] / "corpus"

NEEDS_INPUT_THE_CORPUS_CANNOT_HOLD = {
    # Requires a live registry. Exercised in tests/unit/test_registry_detector.py
    # against a substituted client, because a suite that reaches PyPI fails when
    # PyPI is slow.
    "registry",
    # Requires an advisory database, which is supplied by the operator rather
    # than committed. Exercised in the advisory unit tests.
    "advisory",
}


@pytest.fixture(scope="module")
def findings_by_detector() -> Counter[str]:
    seen: Counter[str] = Counter()
    for group in sorted(CORPUS.iterdir()):
        if not group.is_dir():
            continue
        for case in sorted(group.iterdir()):
            if not case.is_dir():
                continue
            for finding in Scanner().scan(case).findings:
                seen[finding.detector] += 1
    return seen


@requires_malicious_corpus
class TestEveryDetectorRuns:
    def test_the_corpus_exercises_every_detector(self, findings_by_detector) -> None:
        registered = {d.id for d in Registry().detectors()}
        expected = registered - NEEDS_INPUT_THE_CORPUS_CANNOT_HOLD
        silent = sorted(d for d in expected if not findings_by_detector.get(d))
        assert not silent, (
            f"these detectors ship and never fire on the corpus: {silent}. "
            f"A detector that cannot be shown to work is indistinguishable "
            f"from one that found nothing. Add a sample, or document it in "
            f"NEEDS_INPUT_THE_CORPUS_CANNOT_HOLD with the reason."
        )

    def test_the_exception_list_is_not_a_dumping_ground(self) -> None:
        """Every name on it must still be a real detector, and the list must
        stay short enough to read."""
        registered = {d.id for d in Registry().detectors()}
        assert registered >= NEEDS_INPUT_THE_CORPUS_CANNOT_HOLD
        assert len(NEEDS_INPUT_THE_CORPUS_CANNOT_HOLD) <= 3

    def test_it_is_not_vacuous(self, findings_by_detector) -> None:
        assert sum(findings_by_detector.values()) > 40


@requires_malicious_corpus
class TestFindingsStayInsideTheScanTarget:
    """A scan answers about what it was pointed at.

    The VCS detector reads `git log`, which answers about the whole repository,
    and the target is frequently a subdirectory of one -- so scanning
    `packages/api` reported binaries added under `packages/web`. That is noise,
    and it is also an answer to a question nobody asked.
    """

    def test_no_finding_names_a_path_outside_the_target(self) -> None:
        target = CORPUS / "benign" / "ops"
        result = Scanner().scan(target)
        outside = [
            f.location.path
            for f in result.findings
            if f.location.path and not (target / f.location.path).exists()
        ]
        assert not outside, f"findings about files outside the scan target: {outside}"
