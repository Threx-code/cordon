"""`clone` and `pull`: code from elsewhere, scanned before it is checked out or merged.

The check itself is `core/incoming.py`; this is the command line around it, and the hidden
`guard incoming` action the post-checkout and post-merge hooks call.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.core.errors import ExitCode
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    import argparse

    from cordon_scanner.core.config import Config
    from cordon_scanner.core.incoming import IncomingCheck

FAIL_ON_HELP = (
    "also block on findings at or above this severity (default: critical; anything "
    "malicious always blocks)"
)


class IncomingCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        clone = sub.add_parser(
            "clone",
            help="clone a repository, scanning it before any file is checked out",
            description=(
                "Clone without checking out, scan the commit from git's object store, then "
                "check it out. A blocked clone is removed, so nothing of it is left on disk."
            ),
        )
        clone.add_argument("url", help="the repository to clone")
        clone.add_argument("directory", nargs="?", help="where to clone it (default: its name)")
        clone.add_argument("--branch", "-b", metavar="NAME", help="check out this branch")
        clone.add_argument("--fail-on", metavar="SEVERITY", help=FAIL_ON_HELP)
        clone.add_argument(
            "--config",
            metavar="PATH",
            help="your own configuration; the repository's is never read",
        )

        pull = sub.add_parser(
            "pull",
            help="fetch, scan what would be merged, and merge only if it passes",
            description=(
                "Fetch the branch, scan the incoming commit from git's object store, and merge "
                "only when it passes. Findings your checkout already had are not counted again. "
                "A blocked pull leaves the checkout exactly as it was."
            ),
        )
        pull.add_argument("remote", nargs="?", help="the remote (default: the branch's upstream)")
        pull.add_argument("branch", nargs="?", help="the branch on that remote")
        pull.add_argument(
            "--merge",
            action="store_true",
            help="allow a merge commit; fast-forward only by default",
        )
        pull.add_argument("--fail-on", metavar="SEVERITY", help=FAIL_ON_HELP)
        pull.add_argument(
            "--config",
            metavar="PATH",
            help="your own configuration; the incoming code's is never read",
        )
        pull.add_argument(
            "-C", dest="path", default=".", metavar="PATH", help="the repository (default: .)"
        )

    @staticmethod
    def _config(args: argparse.Namespace) -> Config:
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.incoming import Incoming

        base = Config.from_file(args.config) if getattr(args, "config", None) else None
        return Incoming.config(base, getattr(args, "fail_on", None))

    @staticmethod
    def report(check: IncomingCheck, what: str) -> None:
        """What was found, on stderr: the blocking findings first, with where each is."""
        if check.ok:
            note = f" ({check.inherited} already in your checkout)" if check.inherited else ""
            print(f"{PROGRAM}: {what} {check.rev[:12]} passed{note}", file=sys.stderr)
            return
        print(f"\n{PROGRAM}: {what} {check.rev[:12]} BLOCKED", file=sys.stderr)
        for finding in sorted(check.blocking, key=lambda f: f.severity, reverse=True):
            print(
                f"  {finding.severity!s:<8} {finding.rule_id}  {finding.location}", file=sys.stderr
            )
            print(f"           {finding.message}", file=sys.stderr)
        if check.inherited:
            print(
                f"  ({check.inherited} more were already in your checkout and are not counted)",
                file=sys.stderr,
            )

    @classmethod
    def run_clone(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.core.incoming import Incoming

        directory = Path(args.directory or Incoming.default_directory(args.url))
        check = Incoming.clone(args.url, directory, cls._config(args), branch=args.branch)
        if check is None:
            print(
                f"{PROGRAM}: cloned an empty repository; there was nothing to check",
                file=sys.stderr,
            )
            return int(ExitCode.CLEAN)
        cls.report(check, "clone of")
        if not check.ok:
            print(f"\nNothing was checked out, and {directory} was removed.", file=sys.stderr)
            return int(ExitCode.FINDINGS)
        print(f"checked out into {directory}")
        return int(ExitCode.CLEAN)

    @classmethod
    def run_pull(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.core.incoming import Incoming

        root = Path(args.path).resolve()
        check, outcome = Incoming.pull(
            root, cls._config(args), remote=args.remote, branch=args.branch, merge=args.merge
        )
        if check is not None:
            cls.report(check, "incoming")
        print(outcome)
        if check is not None and not check.ok:
            return int(ExitCode.FINDINGS)
        return (
            int(ExitCode.CLEAN)
            if outcome.startswith(("merged", "already"))
            else int(ExitCode.SCANNER_ERROR)
        )

    @classmethod
    def run_hook(cls, args: argparse.Namespace) -> int:
        """`guard incoming <hook> [git's arguments]`: what the incoming shims run.

        Always exits 0. Git ignores a post-checkout or post-merge hook's status, and the undo has
        already happened by the time this returns; the message is what the developer needs.
        """
        from cordon_scanner.core.incoming import Incoming
        from cordon_scanner.sources.git import GitRepository

        info = GitRepository.discover(Path.cwd())
        if info is None:
            return int(ExitCode.CLEAN)
        config = Incoming.config()
        hook, rest = args.hook, list(args.git_args)
        try:
            if hook == "post-checkout" and len(rest) >= 3:
                check = Incoming.after_checkout(info.root, rest[0], rest[1], rest[2], config)
                undone = (
                    "the switch was undone"
                    if rest[0].strip("0")
                    else "its files were removed from the working tree"
                )
            elif hook == "post-merge":
                check = Incoming.after_merge(info.root, config)
                undone = "the merge was undone (git reset --merge ORIG_HEAD)"
            else:
                return int(ExitCode.CLEAN)
        except Exception as exc:  # a hook must report, never crash the git command
            print(
                f"\nWARNING: {PROGRAM} could not check the code this {hook} brought in: {exc}",
                file=sys.stderr,
            )
            print("Do not open or build it until it has been checked.", file=sys.stderr)
            return int(ExitCode.CLEAN)
        if check is None:
            return int(ExitCode.CLEAN)
        cls.report(check, "incoming")
        if not check.ok:
            print(
                f"\n{undone[0].upper()}{undone[1:]}. Nothing in it has been run.", file=sys.stderr
            )
        return int(ExitCode.CLEAN)


__all__ = ["IncomingCommand"]
