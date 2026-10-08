#!/usr/bin/env python3
"""What CI will say about this commit, said before the push. Run by `scripts/prepush.sh`.

The steps are read from `.github/workflows/ci.yml` and run as written, rather than restated
here: a restated copy drifts, and on 8 October 2026 the release's self-scan had drifted from
CI's and blocked 0.6.0 after CI was green. Around them sit the checks for what CI found only on
another platform: `scripts/portability.py` (Windows code pages and paths, POSIX-only imports,
CRLF), the generated tutorials rendered under a runner's environment, and every Dockerfile's
inputs being files the repository tracks.

    python scripts/ci_parity.py            # everything, the full suite included
    python scripts/ci_parity.py --quick    # everything but the suite, perf and fuzz

Runs in a clean clone of the commit being pushed (`prepush.sh` makes it), so what is checked is
what is pushed: not the working tree, its untracked files or its gitignored directories.

Two CI steps cannot run here and are said to be skipped, never passed: the self-scan's ClamAV
pass (a service that downloads its signatures first) and the image builds (Docker in Docker).
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

#: The CI jobs, in the order they are worth failing fast on. `test` is the matrix suite.
JOBS_QUICK = ("lint", "rules", "self-scan", "self-history", "self-records", "determinism")
JOBS_FULL = (*JOBS_QUICK, "fuzz", "performance", "test")
#: Run on the runner and not reproducible in a container; reported as skipped.
NOT_HERE = {"self-images": "builds three images, which needs Docker inside this container"}

#: A runner's environment, which differs from a developer's in ways that have broken tests.
RUNNER_ENV = {
    "CI": "true",
    "GITHUB_ACTIONS": "true",
    "GITHUB_STEP_SUMMARY": os.devnull,
    "XDG_CONFIG_HOME": "/home/runner/.config",
    "COVERAGE_CORE": "sysmon",
}


@dataclass
class Result:
    name: str
    ok: bool
    seconds: float
    note: str = ""
    output: str = ""


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def add(self, result: Result) -> None:
        self.results.append(result)
        mark = "ok  " if result.ok else "FAIL"
        note = f"  ({result.note})" if result.note else ""
        print(f"  {mark}  {result.name}  {result.seconds:.0f}s{note}", flush=True)
        if not result.ok and result.output:
            print("\n".join(f"        {line}" for line in result.output.splitlines()[-40:]))

    @property
    def failed(self) -> list[Result]:
        return [r for r in self.results if not r.ok]


class Shell:
    @staticmethod
    def run(command: str, env: dict[str, str] | None = None, timeout: int = 3600) -> Result:
        started = time.monotonic()
        proc = subprocess.run(  # noqa: S603 - steps come from this repository's own workflow
            ["/bin/bash", "-eo", "pipefail", "-c", command],
            cwd=ROOT,
            env={**os.environ, **RUNNER_ENV, **(env or {})},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return Result(
            name="",
            ok=proc.returncode == 0,
            seconds=time.monotonic() - started,
            output=(proc.stdout + proc.stderr).strip(),
        )


class Workflow:
    """`ci.yml`'s steps, adapted only where a container is not a runner -- and each adaptation
    is printed, so nothing is quietly weakened."""

    EXPRESSION = re.compile(r"\$\{\{.*?\}\}")

    @staticmethod
    def jobs() -> dict[str, dict]:
        return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    @staticmethod
    def steps(job: dict) -> list[tuple[str, dict[str, str], list[str]]]:
        """`(command, env, adaptations)` for each step that runs something here."""
        out = []
        for step in job.get("steps", []):
            command = step.get("run")
            if not command:
                continue  # checkout, setup-python, uploads: the clone and the image are those
            if re.match(r"\s*(python -m )?pip install", command):
                continue  # installed once, before any job, from this commit
            adaptations: list[str] = []
            if Workflow.EXPRESSION.search(command):
                command = Workflow.EXPRESSION.sub("", command)
                adaptations.append("a `${{ }}` expression (the coverage flags) left out")
            if "--clamav" in command:
                command = re.sub(r"[ \t]*--clamav[ \t]+\S+[ \t]*\\?\n?", "", command)
                adaptations.append("ClamAV skipped: CI's service downloads its signatures first")
            env = {k: str(v) for k, v in (step.get("env") or {}).items()}
            out.append((command, env, adaptations))
        return out


class Static:
    @staticmethod
    def tracked() -> list[str]:
        # git from PATH, as every hook resolves it.
        command = ["git", "ls-files"]
        out = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)  # noqa: S603
        return out.stdout.splitlines()

    @staticmethod
    def dockerfile_inputs() -> Result:
        """Every `COPY`/`ADD` source is a tracked file. The pipe image copied
        `action/requirements.txt`, which exists only after a release, and CI's image job failed
        on every commit between releases."""
        started = time.monotonic()
        tracked = Static.tracked()
        problems: list[str] = []
        skipped = ("tests/", "corpus/", "bench/")
        for dockerfile in (p for p in tracked if Path(p).name.startswith("Dockerfile")):
            if dockerfile.startswith(skipped):
                continue
            for number, line in enumerate(
                (ROOT / dockerfile).read_text(encoding="utf-8").splitlines(), 1
            ):
                match = re.match(r"\s*(COPY|ADD)\s+(.*)", line)
                if not match or "--from=" in line:
                    continue
                words = [w for w in shlex.split(match.group(2)) if not w.startswith("--")]
                for source in words[:-1]:
                    pattern = source.rstrip("/").lstrip("./") or "*"
                    hit = any(
                        fnmatch.fnmatch(t, pattern) or t.startswith(pattern + "/") for t in tracked
                    )
                    special = dockerfile == "ci/bitbucket/Dockerfile" and pattern == (
                        "action/requirements.txt"
                    )
                    if not hit and not special:
                        problems.append(f"{dockerfile}:{number}: `{source}` is not a tracked file")
        return Result(
            "Dockerfile inputs are tracked",
            not problems,
            time.monotonic() - started,
            output="\n".join(problems),
        )

    @staticmethod
    def workflows_parse() -> Result:
        started = time.monotonic()
        problems = []
        for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
            try:
                yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                problems.append(f"{path.name}: {exc}")
        return Result(
            "workflows parse", not problems, time.monotonic() - started, output="\n".join(problems)
        )


class Parity:
    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--quick", action="store_true", help="leave out the suite, perf, fuzz")
        args = parser.parse_args()
        report = Report()

        print("before CI's own steps", flush=True)
        portability = Shell.run("python scripts/portability.py")
        portability.name = "portability (Windows, macOS, a runner's environment)"
        report.add(portability)
        report.add(Static.workflows_parse())
        report.add(Static.dockerfile_inputs())
        tutorials = Shell.run(
            "pytest -q -p no:cacheprovider tests/unit/test_tutorial_reference.py",
            env={"HOME": "/home/runner", "APPDATA": "C:\\Users\\runner\\AppData\\Roaming"},
        )
        tutorials.name = "generated tutorials, rendered under a runner's environment"
        report.add(tutorials)
        live = Shell.run("python scripts/live_checks.py --only self-scan")
        live.name = "the release's self-scan (scripts/live_checks.py)"
        report.add(live)

        jobs = Workflow.jobs()
        selected = JOBS_QUICK if args.quick else JOBS_FULL
        for key in selected:
            job = jobs.get(key)
            if job is None:
                report.add(Result(f"ci.yml: {key}", False, 0, output=f"no job `{key}` in ci.yml"))
                continue
            name = job.get("name") or key
            name = Workflow.EXPRESSION.sub("…", name)
            # Each CI job starts from a fresh checkout. Without this, one job's reports
            # (cordon-reports/, history.md, a.json) were in the tree the next job scanned or tested.
            Shell.run("git clean -fdxq -e '*.egg-info' && git checkout -q -- .")
            print(f"ci.yml: {name}", flush=True)
            for index, (command, env, adaptations) in enumerate(Workflow.steps(job), 1):
                result = Shell.run(command, env)
                result.name = f"{key} step {index}: {command.strip().splitlines()[0][:70]}"
                result.note = "; ".join(adaptations)
                report.add(result)
        for key, reason in NOT_HERE.items():
            print(f"  skip  {key}: {reason} (CI runs it)")
        if args.quick:
            print("  skip  test, fuzz, performance: --quick (CI runs them)")

        failed = report.failed
        total = sum(r.seconds for r in report.results)
        print(f"\n{len(report.results) - len(failed)} passed, {len(failed)} failed, {total:.0f}s")
        for result in failed:
            print(f"  FAILED  {result.name}")
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(Parity.main())
