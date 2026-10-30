"""A scan's output does not depend on the process's hash seed.

Python seeds string hashing afresh in every process unless PYTHONHASHSEED is set, so a set's or a
frozenset's iteration order changes from one run to the next. Anything that picks from that order
-- a sort whose key calls two distinct values equal, a `min` or `max` over such a key, a join of a
set -- makes the same scan say different things in two runs: a baseline, a cache or a gate comparing
them sees a change nobody made. The advisory detector named "Upgrade past 1.3" in one run and
"Upgrade past 1.3.0" in another, because the version order calls the two equal and its sort kept the
set's order; the measurement runs set PYTHONHASHSEED=0, which is why none of them saw it.

So each scan here runs in two processes with two seeds, chosen because the old advisory sort answered
differently under them, and every field of every finding must agree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from support import CORPUS

#: Under these two seeds the old advisory sort named different versions (measured: seeds 0-4 and 7
#: gave "1.3.0", 5 and 6 gave "1.3").
SEEDS = ("0", "5")

SCAN = """
import json, sys
from pathlib import Path
from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector

target, kind = Path(sys.argv[1]), sys.argv[2]
config = Config.default().with_overrides(use_cache=False)
if kind == "two-spellings":
    records = [
        Advisory(ecosystem="maven", name="org.example:lib", versions=("1.2", "1.3"), summary="s",
                 identifier="GHSA-aaaa-bbbb-cccc"),
        Advisory(ecosystem="maven", name="org.example:lib", versions=("1.2", "1.3.0"), summary="s",
                 identifier="GHSA-dddd-eeee-ffff"),
    ]
    scanner = Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),))
elif kind == "tag-cycle":
    # A git tag among PEP 440 versions: compared by spelling against them, so the three order in
    # a cycle (tag < v1.4.0a0 < 1.13.1 < tag), as torch's advisories have them.
    records = [
        Advisory(ecosystem="pypi", name="examplepkg", versions=("v1.4.0a0", "malfet/tag-ec6f767",
                 "1.13.1"), summary="s", identifier="GHSA-gggg-hhhh-jjjj"),
    ]
    scanner = Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),))
else:
    scanner = Scanner(config)
findings = []
for finding in scanner.scan(target).findings:
    record = finding.to_dict()
    if record.get("rule_id") == "OPERATIONAL.INTEL.STALE":
        record["message"] = ""  # it states the intel's age, which moves with the clock
    findings.append(record)
print(json.dumps(findings, sort_keys=True, default=str))
"""


class HashOrderKit:
    @staticmethod
    def scan(target: Path, kind: str, seed: str, home: Path) -> str:
        environment = {
            **os.environ,
            "PYTHONHASHSEED": seed,
            "CORDON_OFFLINE": "1",
            # One home for both runs, so the install key (and every secret's keyed hash) is one.
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home / "cache"),
        }
        run = subprocess.run(
            [sys.executable, "-c", SCAN, str(target), kind],
            capture_output=True,
            text=True,
            env=environment,
            timeout=600,
            check=False,
        )
        assert run.returncode == 0, run.stderr[-2000:]
        return run.stdout

    @staticmethod
    def differences(first: str, second: str) -> list[str]:
        a, b = json.loads(first), json.loads(second)
        if len(a) != len(b):
            return [f"{len(a)} findings against {len(b)}"]
        return [
            f"{x.get('rule_id')} {field}: {str(x.get(field))[:120]!r} against {str(y.get(field))[:120]!r}"
            for x, y in zip(a, b, strict=True)
            for field in sorted(set(x) | set(y))
            if x.get(field) != y.get(field)
        ][:10]

    @staticmethod
    def pom(root: Path) -> Path:
        root.mkdir()
        (root / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>y</artifactId>"
            "<version>1</version><dependencies><dependency><groupId>org.example</groupId>"
            "<artifactId>lib</artifactId><version>1.2</version></dependency></dependencies></project>",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def requirements(root: Path) -> Path:
        root.mkdir()
        (root / "requirements.txt").write_text("examplepkg==1.13.1\n", encoding="utf-8")
        return root


class TestTheHashSeedChangesNothing:
    def test_advisories_spelling_one_version_two_ways(self, tmp_path: Path) -> None:
        project = HashOrderKit.pom(tmp_path / "project")
        runs = [HashOrderKit.scan(project, "two-spellings", seed, tmp_path) for seed in SEEDS]
        found = json.loads(runs[0])
        assert any("Upgrade past 1.3" in str(f.get("remediation")) for f in found), found
        assert not HashOrderKit.differences(*runs), HashOrderKit.differences(*runs)

    def test_a_tag_among_versions_names_one_version(self, tmp_path: Path) -> None:
        # The three versions compare in a cycle, so the old sort named whichever its input put
        # last: under seeds 0, 1 and 2 it said v1.4.0a0, 1.13.1 and malfet/tag-ec6f767 (measured).
        project = HashOrderKit.requirements(tmp_path / "project")
        runs = [HashOrderKit.scan(project, "tag-cycle", seed, tmp_path) for seed in ("0", "1", "2")]
        found = json.loads(runs[0])
        assert any("Upgrade past" in str(f.get("remediation")) for f in found), found
        assert not HashOrderKit.differences(*runs[:2]), HashOrderKit.differences(*runs[:2])
        assert not HashOrderKit.differences(runs[0], runs[2]), HashOrderKit.differences(
            runs[0], runs[2]
        )

    @pytest.mark.parametrize("part", ["benign", "malicious"])
    def test_the_repository_corpus(self, tmp_path: Path, part: str) -> None:
        # Copied, so both runs read the same files from a place no other test writes to.
        target = tmp_path / part
        shutil.copytree(CORPUS / part, target)
        runs = [HashOrderKit.scan(target, "default", seed, tmp_path) for seed in SEEDS]
        assert json.loads(runs[0]), "the scan found nothing, so the comparison proves nothing"
        assert not HashOrderKit.differences(*runs), HashOrderKit.differences(*runs)
