"""`bundle create`, `bundle verify` and `bundle install`: an offline bundle for an air-gapped
install, refused unless it verifies."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM


class BundleCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        bundle = sub.add_parser(
            "bundle",
            help="build and verify an offline bundle for an air-gapped install",
        ).add_subparsers(dest="bundle_command")
        bundle_create = bundle.add_parser("create", help="build a bundle from a directory")
        bundle_create.add_argument("source", help="directory holding the files to bundle")
        bundle_create.add_argument("--output", "-o", required=True, metavar="PATH")
        bundle_verify = bundle.add_parser("verify", help="check a bundle against its manifest")
        bundle_verify.add_argument("bundle_file", metavar="BUNDLE")
        bundle_install = bundle.add_parser("install", help="verify a bundle, then extract it")
        bundle_install.add_argument("bundle_file", metavar="BUNDLE")
        bundle_install.add_argument("--into", required=True, metavar="DIR")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Build, check, or install an offline bundle.

        `verify` fails closed. An air-gapped operator who is told a bundle is
        merely questionable will install it, because they carried it across a
        room to do exactly that, and the alternative is going back for another
        one. So there is no questionable: it verifies or it is refused.
        """
        from cordon_scanner.engine.bundle import Bundle

        action = getattr(args, "bundle_command", None)
        if action is None:
            print(f"{PROGRAM}: bundle needs create, verify or install", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        if action == "create":
            source = Path(args.source)
            if not source.is_dir():
                raise ConfigError(f"{source} is not a directory")
            files = [
                (str(p.relative_to(source)).replace(os.sep, "/"), p)
                for p in sorted(source.rglob("*"))
                if p.is_file() and not p.is_symlink()
            ]
            written = Bundle.create(Path(args.output), files=files)
            print(f"wrote {written} ({len(files)} file(s))")
            print(
                "This proves internal consistency. Sign it before it crosses the air gap, "
                "or the far end can check only that it is the bundle its own manifest describes."
            )
            return int(ExitCode.CLEAN)

        report = Bundle.verify(Path(args.bundle_file))
        if action == "verify":
            if report.ok:
                print(report.summary())
                return int(ExitCode.CLEAN)
            print(f"{PROGRAM}: bundle REFUSED", file=sys.stderr)
            for problem in report.problems:
                print(f"  {problem}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        # install
        if not report.ok:
            print(f"{PROGRAM}: bundle REFUSED; nothing was written", file=sys.stderr)
            for problem in report.problems:
                print(f"  {problem}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        into = Path(args.into)
        installed = Bundle.install(Path(args.bundle_file), into)
        if not installed.ok:
            print(f"{PROGRAM}: bundle REFUSED; nothing was written", file=sys.stderr)
            for problem in installed.problems:
                print(f"  {problem}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        print(f"installed {installed.checked} file(s) into {into}")
        if not installed.authenticated:
            print(f"Not authenticated: {installed.summary()}", file=sys.stderr)
        return int(ExitCode.CLEAN)


__all__ = ["BundleCommand"]
