"""`verify`: whether this Cordon installation is the one its release built (release item 75).

Exit codes keep the CLI's stable meanings: 0 verified (only after the online provenance step), 1
modified, 4 incomplete -- consistent with its own RECORD, or unverified, told apart by `state` in
`--format json` -- and 3 for an argument that is not a site-packages directory. Offline is never
reported as verified: whoever can edit Cordon's files can edit its RECORD too.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM

LIMIT = (
    "Offline this checks the installation against its own RECORD. It catches accidental and partial "
    "changes, not a RECORD rewritten to match them. For the strong form, run it from a separate, "
    "trusted copy (a pinned container image, or `pipx run cordon-scanner==<version>`) with --target."
)


class VerifyInstallCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        command = sub.add_parser(
            "verify",
            help="check this Cordon installation against the release that built it",
        )
        command.add_argument(
            "--target",
            metavar="SITE_PACKAGES",
            help="verify the installation in this site-packages directory, not the running one",
        )
        command.add_argument("--format", choices=("text", "json"), default="text")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        from cordon_scanner.intel.provenance.install_verify import InstallRecord, InstallState

        target = Path(args.target) if getattr(args, "target", None) else None
        if target is not None and not target.is_dir():
            raise ConfigError(f"{target} is not a directory")
        report = InstallRecord.check(target)
        code = {
            InstallState.VERIFIED: ExitCode.CLEAN,
            InstallState.MODIFIED: ExitCode.FINDINGS,
            InstallState.CONSISTENT: ExitCode.INCOMPLETE,
            InstallState.UNVERIFIED: ExitCode.INCOMPLETE,
        }[report.state]
        if args.format == "json":
            print(json.dumps({**report.as_dict(), "exit": int(code), "limit": LIMIT}, indent=2))
            return int(code)
        out = sys.stdout if report.state is not InstallState.MODIFIED else sys.stderr
        version = f" {report.version}" if report.version else ""
        print(f"{PROGRAM}{version}: installation {report.state.value}", file=out)
        if report.reason:
            print(f"  {report.reason}", file=out)
        for problem in report.problems:
            print(f"  {problem}", file=out)
        if report.state is not InstallState.VERIFIED:
            print(LIMIT, file=out)
        return int(code)


__all__ = ["VerifyInstallCommand"]
