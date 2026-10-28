"""`guard verify`, `guard install` and `guard update`: the scanner's self-integrity manifest and the
fail-closed git hooks, plus the hidden `guard incoming` entry point the hooks call."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM


class GuardCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        guard_cmd = sub.add_parser("guard", help="scanner self-integrity and git hook installation")
        guard_sub = guard_cmd.add_subparsers(dest="guard_command", metavar="<action>")
        for action, description in (
            ("verify", "check that the guard is intact"),
            ("install", "install fail-closed git hooks"),
            ("update", "regenerate the guard hash manifest"),
        ):
            parser_ = guard_sub.add_parser(action, help=description)
            parser_.add_argument("path", nargs="?", default=".")
            if action == "verify":
                parser_.add_argument(
                    "--manifest-only",
                    action="store_true",
                    help=(
                        "check only that every file the guard manifest lists matches it; "
                        "for CI, which has no hooks to check"
                    ),
                )
            if action == "install":
                parser_.add_argument(
                    "--global",
                    dest="global_",
                    action="store_true",
                    help=(
                        "install into git's template directory, so every repository cloned "
                        "or created from now on has the hooks"
                    ),
                )
                parser_.add_argument(
                    "--force",
                    action="store_true",
                    help=(
                        "replace a pre-existing non-cordon hook. Without this such a "
                        "hook is preserved and a backup is written beside it"
                    ),
                )

        # The incoming shims' entry point: hidden, because nobody types it.
        incoming_hook = guard_sub.add_parser("incoming")
        incoming_hook.add_argument("hook", choices=("post-checkout", "post-merge"))
        incoming_hook.add_argument("git_args", nargs="*")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        from cordon_scanner.engine.guard import Guard

        action = args.guard_command or "verify"
        root = Path(getattr(args, "path", "."))

        if action == "incoming":
            from cordon_scanner.cli.incoming import IncomingCommand

            return IncomingCommand.run_hook(args)

        if action == "install" and getattr(args, "global_", False):
            template, installed = Guard.install_global(force=getattr(args, "force", False))
            for hook in installed:
                print(f"installed {template / 'hooks' / hook}")
            print(
                f"\nEvery repository cloned or created from now on starts with these hooks: a "
                f"clone, branch\nswitch or pull is checked before anything acts on it, and "
                f"undone if it is blocked.\nFor repositories you already have, run "
                f"`{PROGRAM} guard install` in each."
            )
            return int(ExitCode.CLEAN)

        if action == "install":
            installed = Guard.install_hooks(root, force=getattr(args, "force", False))
            for hook in installed:
                print(f"installed .git/hooks/{hook}")
            print(
                f"\nHooks live in .git/hooks, which git does not track, so no commit, "
                f"branch\nswitch, merge or `git clean` removes them. Each fails closed: "
                f"if {PROGRAM}\ncannot run, the operation is refused rather than allowed."
            )
            return int(ExitCode.CLEAN)

        if action == "update":
            manifest = Guard.write_manifest(root)
            print(f"wrote {manifest}")
            print(
                "\nCommit this file. Its only purpose is to be reviewed: an attacker who\n"
                "edits a guard can regenerate it in the same commit, and no self-hosted\n"
                "check can prevent that. What it guarantees is that the change cannot be\n"
                "silent."
            )
            return int(ExitCode.CLEAN)

        if action == "verify":
            report = Guard.verify(root, manifest_only=getattr(args, "manifest_only", False))
            if report.ok:
                print("guard intact")
                return int(ExitCode.CLEAN)
            for problem in report.problems:
                print(f"{problem.status}: {problem.detail}", file=sys.stderr)
                print(f"  fix: {problem.remediation}", file=sys.stderr)
            return int(ExitCode.FINDINGS)

        raise ConfigError(f"unknown guard action: {action}")


__all__ = ["GuardCommand"]
