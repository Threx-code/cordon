"""`baseline create` and `baseline compare`: record the findings a repository chooses to carry,
and report what falls outside them."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode

if TYPE_CHECKING:
    from cordon_scanner.sources.base import FileSource


class BaselineCommand:
    @classmethod
    def add_parser(cls, sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        baseline = sub.add_parser(
            "baseline",
            help="record known findings so a tool can be adopted incrementally",
        ).add_subparsers(dest="baseline_command")
        create = baseline.add_parser("create", help="record the current findings")
        create.add_argument("target", nargs="?", default=".")
        create.add_argument(
            "--output", "-o", default="cordon-baseline.json", help="where to write it"
        )
        create.add_argument("--policy", metavar="PATH", default=None)
        cls._add_scope(create)
        compare = baseline.add_parser("compare", help="report findings outside the baseline")
        compare.add_argument("target", nargs="?", default=".")
        compare.add_argument(
            "baseline_file", nargs="?", default="cordon-baseline.json", metavar="BASELINE"
        )
        compare.add_argument("--policy", metavar="PATH", default=None)
        cls._add_scope(compare)

    @staticmethod
    def _add_scope(parser: argparse.ArgumentParser) -> None:
        """The one flag that decides which files a baseline is about.

        On `create` and `compare` both, from one definition. A baseline created
        over tracked files and compared against a whole working tree reports
        every ignored file as a new finding, which is the failure the shared
        default exists to prevent -- and two separately declared flags with the
        same name is how two commands come to disagree about one.
        """
        parser.add_argument(
            "--all-files",
            action="store_true",
            help=(
                "include files git ignores; by default a baseline inside a "
                "repository covers tracked files only"
            ),
        )

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        """Create or compare a baseline.

        Baselines exist so the tool can be adopted into an existing codebase
        without demanding the whole backlog be fixed on day one. The
        alternative -- turn it on, get four hundred findings, turn it off -- is
        the most common way a security tool fails to be adopted at all.

        `compare` never writes. Refreshing a baseline has to be a separate,
        deliberate act, or the command run in CI to detect new findings would
        also be the command that absorbs them.
        """
        from cordon_scanner import Scanner
        from cordon_scanner.decide.policy import Baseline
        from cordon_scanner.foundation.config.resolver import ConfigResolver

        target = Path(args.target)
        if not target.exists():
            raise CordonError(f"target does not exist: {target}")

        config = ConfigResolver.resolve(
            root=target if target.is_dir() else target.parent,
            policy_path=args.policy,
        )
        result = Scanner(config, source=cls._select_source(args, target)).scan(target)
        action = args.baseline_command or "create"

        if action == "create":
            # Malicious findings are recorded like any other, and refused at
            # apply time. Filtering them out here would make the file look
            # complete while quietly excluding the findings that matter.
            destination = Path(args.output)
            if destination == Path("cordon-baseline.json"):
                root = target if target.is_dir() else target.parent
                destination = root / "cordon-baseline.json"
            written = Baseline.from_result(result).write(destination)
            count = len(result.findings)
            print(f"wrote {written} with {count} finding(s)")
            print(
                "  Review it before committing. Every entry is something this "
                "repository is choosing not to fix yet."
            )
            return int(ExitCode.CLEAN)

        if action == "compare":
            # Resolved against the target, not the working directory. A baseline
            # belongs to the repository it describes, and defaulting to the
            # caller's cwd means `cordon baseline compare ../other-repo` silently
            # compares one repository against another's debt.
            path = Path(args.baseline_file)
            if path == Path("cordon-baseline.json"):
                root = target if target.is_dir() else target.parent
                path = root / "cordon-baseline.json"
            baseline = Baseline.from_file(path)
            added, cleared = baseline.compare(result)

            if cleared:
                print(f"{len(cleared)} baselined finding(s) no longer occur:")
                for fingerprint in cleared[:20]:
                    print(f"  {fingerprint}")
                print("  Regenerate the baseline so it shrinks with the backlog.")

            if not added:
                print("no findings outside the baseline")
                return int(ExitCode.CLEAN)

            print(f"\n{len(added)} finding(s) not in the baseline:")
            for finding in sorted(added, key=lambda f: f.sort_key()):
                print(f"  {finding.severity} {finding.rule_id} at {finding.location}")
            return int(ExitCode.FINDINGS)

        raise ConfigError(f"unknown baseline action: {action}")

    @classmethod
    def _select_source(cls, args: argparse.Namespace, target: Path) -> FileSource | None:
        """Tracked files by default, because a baseline is a committed artefact.

        The bug this fixes: `baseline create` walked the working tree, so a
        repository with a local `.env`, a `venv/`, a `node_modules/` or a
        `coverage/` directory got those paths written into a file that is then
        committed. Three things are wrong with that at once.

        The entries cannot be reproduced. A fingerprint over a path no other
        clone has is debt nobody else can see, clear or verify, and `compare`
        reports it as "no longer occurs" on every machine but the one that wrote
        it.

        The baseline misrepresents the repository. A reviewer reading it to find
        out what is being carried is reading findings about files that are not
        part of the project.

        And a secret scanner reading untracked `.env` files by default is the
        wrong default whatever it does with what it finds. Nothing leaks here --
        baseline entries carry a fingerprint, a rule id and a path, never the
        value, and evidence is hash-only throughout -- but the shape of the
        mistake is the one this tool exists to object to elsewhere.

        Unlike `_git_source`, a tree that is not a repository is not an error.
        `--tracked` on `scan` is a promise about which bytes were read and must
        fail rather than quietly widen; this is a default about which files are
        worth recording, and refusing to baseline an unversioned directory would
        be refusing to do the thing that was asked. It says which it did, both
        ways, because a scope a reader has to infer is a scope they will get
        wrong.
        """
        if args.all_files:
            return None

        from cordon_scanner.sources.git import GitPathSource, GitRepository

        info = GitRepository.discover(target)
        if info is None:
            print(
                "cordon: not a git repository; the baseline covers every file under the target",
                file=sys.stderr,
            )
            return None

        paths = GitRepository(info.root).tracked_files()
        print(
            f"cordon: the baseline covers {len(paths)} tracked file(s); "
            "pass --all-files to include paths git ignores",
            file=sys.stderr,
        )
        return GitPathSource(paths, mode="tracked")


__all__ = ["BaselineCommand"]
