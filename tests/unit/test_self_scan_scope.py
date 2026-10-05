"""Every self-scan leaves out the same deliberate attacks.

Cordon scans itself in three places: `make scan`, the CI `self-scan` job, and the release's live
check. The corpus and the agent benchmark hold attack samples on purpose, so each scan excludes
them. The lists are written out three times, and on 2026-10-05 `bench/**` reached two of them:
the release's live check scanned the benchmark, reported its planted attacks, and blocked v0.5.0
before anything was published. This keeps the three in step for the paths that must never be
scanned.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: Directories of deliberate attack samples, which no self-scan may read.
ATTACK_SAMPLES = ("corpus/**", "bench/**")


class TestSelfScanScope:
    def test_every_self_scan_excludes_the_attack_samples(self) -> None:
        places = {
            "Makefile": (ROOT / "Makefile").read_text(encoding="utf-8"),
            ".github/workflows/ci.yml": (ROOT / ".github" / "workflows" / "ci.yml").read_text(
                encoding="utf-8"
            ),
            "scripts/live_checks.py": (ROOT / "scripts" / "live_checks.py").read_text(
                encoding="utf-8"
            ),
        }
        missing = [
            f"{place} does not exclude {pattern}"
            for place, text in places.items()
            for pattern in ATTACK_SAMPLES
            if pattern not in text
        ]
        assert not missing, missing
