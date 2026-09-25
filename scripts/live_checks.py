#!/usr/bin/env python3
"""The checks that need a live registry, and therefore cannot sit in CI's main job.

Everything in `make check` runs offline, deliberately: the suite must pass in an
air-gap and must not go red because PyPI is slow. That leaves a gap, and the gap
is where the expensive defects live. Four of them shipped at once in 0.3.0:

* the `[attest]` verifier called `verify_artifact` on DSSE bundles, so every
  genuine npm and PyPI attestation was reported as a forgery, at CRITICAL;
* Yarn Berry's cache checksum was compared against npm's tarball hash, which it
  can never equal, so every dependency of every Berry lockfile was a CRITICAL
  hash mismatch;
* `--timeout` did not reach the network phase, so a bounded scan ran unbounded;
* a scan whose entire online layer failed still reported `complete: true`.

Every one of them is invisible to a mocked test -- the mock is what encodes the
assumption that turned out to be wrong -- and every one is caught by a single
real request. So these run somewhere with egress, on a schedule and before a
tag, and a failure here blocks a release rather than a pull request.

    python scripts/live_checks.py            # all of them
    python scripts/live_checks.py --only attestation yarn

Exit 0 when every check passed, 1 when one did not, 2 when the harness itself
could not run. A check that cannot reach the network at all exits 2, not 1:
"the registry was down" and "the scanner is wrong" are opposite facts, and a
gate that conflates them gets switched off.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

#: A release published by the Sigstore project itself, with provenance that is
#: genuine and verifiable. Pinned rather than resolved: the point of the check
#: is that a KNOWN-GOOD attestation verifies, so the artefact must not move.
ATTESTED_NPM = ("sigstore", "4.1.0")
ATTESTED_NPM_INTEGRITY = (
    "sha512-/fUgUhYghuLzVT/gaJoeVehLCgZiUxPCPMcyVNY0lIf/"
    "cTCz58K/WTI7PefDarXxp9nUKpEwg1yyz3eSBMTtgA=="
)

#: The genuine registry hash for a package every Berry lockfile has, used as the
#: control: the Berry checksum must NOT conflict, and a real mismatch must.
YARN_PACKAGE = ("lodash", "4.17.21")
YARN_BERRY_CHECKSUM = (
    "10c0/d8cbea072bb08655bb4c989da418994b073a608dffa608b09ac04b43a791b12"
    "aeae7cd7ad919aa4c925f33b48490b5cfe6c1f71d827956071dae2e7bb3a6b74c"
)

#: A version its publisher withdrew. Yanking is permanent, so this stays true.
YANKED_PYPI = ("requests", "2.32.0")

TIMEOUT_BUDGET = 5
TIMEOUT_TOLERANCE = 4.0
"""Seconds of slack over the budget. Generous: this asserts the deadline is
*honoured*, not that the machine is fast."""


class CheckFailed(Exception):
    """A check ran and the answer was wrong."""


class CannotRun(Exception):
    """The harness could not get far enough to have an opinion."""


def _scan(target: Path, *args: str) -> dict[str, Any]:
    """Run a scan and return its JSON, or raise `CannotRun`."""
    argv = [
        sys.executable,
        "-m",
        "cordon_scanner",
        "scan",
        str(target),
        "--format",
        "json",
        "--no-cache",
        *args,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    if not proc.stdout.strip():
        raise CannotRun(f"scan produced no output: {proc.stderr.strip()[:400]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise CannotRun(f"scan output was not JSON: {exc}") from exc


def _ids(result: dict[str, Any]) -> list[str]:
    return [f["rule_id"] for f in result.get("findings", [])]


def _reachable() -> None:
    """Confirm the registries answer before any check blames the scanner."""
    for url in ("https://registry.npmjs.org/lodash", "https://pypi.org/pypi/requests/json"):
        try:
            with urllib.request.urlopen(url, timeout=20):  # noqa: S310
                pass
        except (urllib.error.URLError, OSError) as exc:
            raise CannotRun(f"{url} is unreachable: {exc}") from exc


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def check_attestation(tmp: Path) -> str:
    """A genuine attestation must verify, and must not be called a forgery."""
    try:
        import sigstore  # noqa: F401
    except ImportError as exc:
        raise CannotRun("the [attest] extra is not installed") from exc

    name, version = ATTESTED_NPM
    work = tmp / "attest"
    work.mkdir()
    (work / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "a",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {"name": "a", "version": "1.0.0", "dependencies": {name: version}},
                    f"node_modules/{name}": {
                        "version": version,
                        "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
                        "integrity": ATTESTED_NPM_INTEGRITY,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    found = _ids(_scan(work, "--online"))
    if "VULNERABLE.PROVENANCE.INVALID.001" in found:
        raise CheckFailed(
            f"{name}@{version} has genuine provenance and was reported INVALID. "
            f"This is the shape of calling the wrong sigstore API for the bundle type."
        )
    return f"{name}@{version} provenance did not report INVALID"


def check_yarn_berry(tmp: Path) -> str:
    """A Berry cache checksum is not a registry digest and must not conflict."""
    name, version = YARN_PACKAGE
    work = tmp / "yarn"
    work.mkdir()
    (work / "package.json").write_text(
        json.dumps({"name": "y", "version": "1.0.0", "dependencies": {name: version}}),
        encoding="utf-8",
    )
    (work / "yarn.lock").write_text(
        "__metadata:\n"
        "  version: 8\n"
        "  cacheKey: 10c0\n"
        "\n"
        f'"{name}@npm:{version}":\n'
        f"  version: {version}\n"
        f'  resolution: "{name}@npm:{version}"\n'
        f"  checksum: {YARN_BERRY_CHECKSUM}\n"
        "  languageName: node\n"
        "  linkType: hard\n",
        encoding="utf-8",
    )
    found = _ids(_scan(work, "--online"))
    if "SUSPECT.PROVENANCE.MISMATCH.001" in found:
        raise CheckFailed(
            "an untouched Yarn Berry lockfile reported a CRITICAL hash mismatch. "
            "Berry's `checksum:` is a hash of its own cache entry and can never "
            "equal what npm serves."
        )
    return "a pristine Berry lockfile reported no hash mismatch"


def check_yank(tmp: Path) -> str:
    """A withdrawn release must still be reported as withdrawn."""
    name, version = YANKED_PYPI
    work = tmp / "yank"
    work.mkdir()
    (work / "requirements.txt").write_text(f"{name}=={version}\n", encoding="utf-8")
    found = _ids(_scan(work, "--online"))
    if "SUSPECT.DEPENDENCY.YANKED.001" not in found:
        raise CheckFailed(
            f"{name}=={version} was yanked by its publisher and was not reported. "
            f"The online layer is not producing findings."
        )
    return f"{name}=={version} reported as withdrawn"


def check_timeout(tmp: Path) -> str:
    """`--timeout` must bound the network phase, not just the file phase."""
    names = [f"pkg-{i:03d}" for i in range(120)]
    work = tmp / "timeout"
    work.mkdir()
    packages: dict[str, Any] = {
        "": {"name": "t", "version": "1.0.0", "dependencies": dict.fromkeys(names, "1.0.0")}
    }
    for n in names:
        packages[f"node_modules/{n}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/{n}/-/{n}-1.0.0.tgz",
        }
    (work / "package-lock.json").write_text(
        json.dumps({"name": "t", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}),
        encoding="utf-8",
    )
    started = time.monotonic()
    result = _scan(work, "--online", "--timeout", str(TIMEOUT_BUDGET))
    elapsed = time.monotonic() - started
    if elapsed > TIMEOUT_BUDGET + TIMEOUT_TOLERANCE:
        raise CheckFailed(
            f"--timeout {TIMEOUT_BUDGET} took {elapsed:.1f}s. The deadline is not "
            f"reaching the network detectors."
        )
    if result.get("complete") is True and elapsed > TIMEOUT_BUDGET:
        raise CheckFailed("the scan stopped early and still reported complete: true")
    return f"--timeout {TIMEOUT_BUDGET} honoured ({elapsed:.1f}s)"


def check_self_scan(tmp: Path) -> str:
    """Cordon must pass its own gate, on a tree that includes its data.

    `--tracked`, for the reason the `scan` target in the Makefile carries it: without it
    this walks gitignored paths as well, and `.iac-schema/` holds third-party Terraform and
    CloudFormation fixtures pulled down for schema work. Scanning those reported 69 critical
    and 726 high findings against code this project neither wrote nor ships, and blocked the
    release for anyone who had done that work. A fresh CI checkout has no such directory, so
    the gate passed there and failed only locally - the worst way round for a check whose job
    is to be believed.
    """
    del tmp
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "cordon_scanner",
            "scan",
            str(ROOT),
            "--tracked",
            "--exclude",
            "corpus/**",
            "--exclude",
            "build/**",
            "--exclude",
            "dist/**",
            "--fail-on",
            "medium",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if proc.returncode != 0:
        tail = "\n".join(proc.stdout.strip().splitlines()[-12:])
        raise CheckFailed(f"the self-scan gate exited {proc.returncode}:\n{tail}")
    return "the self-scan gate passed"


CHECKS: dict[str, Callable[[Path], str]] = {
    "attestation": check_attestation,
    "yarn": check_yarn_berry,
    "yank": check_yank,
    "timeout": check_timeout,
    "self-scan": check_self_scan,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--only", nargs="+", choices=sorted(CHECKS), metavar="CHECK")
    args = parser.parse_args()

    selected = args.only or sorted(CHECKS)

    if not shutil.which(sys.executable):  # pragma: no cover - defensive
        print("cannot locate the interpreter", file=sys.stderr)
        return 2

    try:
        _reachable()
    except CannotRun as exc:
        print(f"SKIPPED  every check: {exc}", file=sys.stderr)
        return 2

    failed, blocked = 0, 0
    with tempfile.TemporaryDirectory(prefix="cordon-live-") as raw:
        tmp = Path(raw)
        for name in selected:
            try:
                detail = CHECKS[name](tmp)
            except CheckFailed as exc:
                print(f"FAILED   {name}: {exc}")
                failed += 1
            except CannotRun as exc:
                print(f"SKIPPED  {name}: {exc}")
                blocked += 1
            else:
                print(f"OK       {name}: {detail}")

    print()
    if failed:
        print(f"{failed} check(s) failed. This blocks a release.", file=sys.stderr)
        return 1
    if blocked:
        print(f"{blocked} check(s) could not run; none failed.", file=sys.stderr)
        return 2
    print(f"all {len(selected)} live check(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
