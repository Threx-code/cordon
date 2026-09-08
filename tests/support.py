"""Paths to fixture data, and the guards for when it is absent.

The source distribution ships the test suite -- for a security tool, re-running
the suite is the only check a downstream packager can make that does not require
trusting this repository -- but it does not ship `corpus/`. That directory holds
working malicious samples: install hooks that exfiltrate environment variables,
droppers, a bidirectional-override trojan. Uploading those to a package index is
both bad practice and a good way to have the release pulled by the index's own
malware scanning.

So the shipped suite is missing data that eight tests need. The choice is
between those tests failing on every downstream run and skipping with a reason
that says why. They skip: a suite that fails out of the box teaches its reader
that failures are normal, which is the opposite of what shipping it was for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
WORKFLOWS = ROOT / ".github" / "workflows"

requires_corpus = pytest.mark.skipif(
    not CORPUS.is_dir(),
    reason="corpus/ holds live malicious samples and is not shipped in the sdist",
)

requires_workflows = pytest.mark.skipif(
    not WORKFLOWS.is_dir(),
    reason=".github/ is not shipped in the sdist",
)

__all__ = ["CORPUS", "ROOT", "WORKFLOWS", "requires_corpus", "requires_workflows"]
