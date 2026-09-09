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


def assemble(*parts: str) -> str:
    """Join fixture parts at runtime.

    Fabricated credentials and payloads have to keep the shape of the real
    thing, or the tests prove nothing about the detectors. They also must not
    trip Cordon's scan of its own repository, and the tool gets no exception
    for itself.

    Concatenation used to be the way that was managed. It no longer is: Cordon
    folds constant `+` chains and matches the joined value, because splitting a
    token across a `+` is the cheapest way to hide one from a secret scanner.
    `"ghp_" + "..."` is a constant expression, and the tool is right to read it
    as the token it spells.

    Passing the parts as arguments defers the join to call time, where there is
    no constant to fold. That is what "assembled at runtime" has to mean for it
    to be true.
    """
    return "".join(parts)


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
    "assemble",
    "requires_corpus",
    "requires_malicious_corpus",
    "requires_workflows",
]
