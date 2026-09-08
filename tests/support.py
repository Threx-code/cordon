"""Paths to fixture data, and the guards for when it is absent.

The source distribution ships the test suite, because for a security tool
re-running the suite is the only check a downstream packager can make that does
not require trusting this repository.

It ships `corpus/benign` and not `corpus/malicious`. The split is deliberate and
the consequences are worth stating plainly rather than discovering:

`corpus/benign` is ordinary source that must produce nothing above `low`. It
carries no payload, so it ships, and the false-positive suite -- half of what
decides whether this product works -- runs downstream unchanged.

`corpus/malicious` holds detection fixtures: an install hook that posts the
environment, a dropper, a bidirectional-override trojan. They are inert, a few
lines each, and point only at RFC 2606 reserved domains. They are still exactly
the shapes a package index's own malware scanning looks for in an sdist, and a
first release pulled on upload helps nobody. So the detection suite cannot run
from an sdist, and says so when it skips rather than passing quietly: clone the
repository at the release tag to run it.

What must never happen is the third option, where a partial corpus leaves the
detection tests collecting zero cases and reporting success. `test_corpus.py`
asserts its discovery found something whenever the directory exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
BENIGN = CORPUS / "benign"
MALICIOUS = CORPUS / "malicious"
WORKFLOWS = ROOT / ".github" / "workflows"

requires_corpus = pytest.mark.skipif(
    not CORPUS.is_dir(),
    reason="corpus/ is not present",
)

requires_malicious_corpus = pytest.mark.skipif(
    not MALICIOUS.is_dir(),
    reason=(
        "corpus/malicious/ is not shipped in the sdist; clone the repository at "
        "the release tag to run the detection suite"
    ),
)

requires_workflows = pytest.mark.skipif(
    not WORKFLOWS.is_dir(),
    reason=".github/ is not shipped in the sdist",
)

__all__ = [
    "BENIGN",
    "CORPUS",
    "MALICIOUS",
    "ROOT",
    "WORKFLOWS",
    "requires_corpus",
    "requires_malicious_corpus",
    "requires_workflows",
]
