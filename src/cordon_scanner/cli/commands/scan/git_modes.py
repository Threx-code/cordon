"""`scan --staged`, `--tracked` and `--git-diff`: the file source each git mode reads, refused rather
than widened when it cannot be honoured."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.foundation.errors import ConfigError

if TYPE_CHECKING:
    from cordon_scanner.sources.base import FileSource


class GitModes:
    @staticmethod
    def source(args: argparse.Namespace, target: Path) -> FileSource | None:
        """Build the file source for a git mode, or None for the working tree.

        Every failure here is a hard error rather than a fallback. Falling back to
        the working tree when `--staged` cannot be honoured is the worst available
        outcome: the hook reports success having scanned the wrong bytes, which is
        precisely the bypass staged mode exists to close.
        """
        if not (args.staged or args.tracked or args.git_diff):
            return None

        from cordon_scanner.foundation.errors import SourceError
        from cordon_scanner.sources.git import GitIndexSource, GitPathSource, GitRepository

        flag = "--staged" if args.staged else "--tracked" if args.tracked else "--git-diff"

        info = GitRepository.discover(target)
        if info is None:
            raise ConfigError(
                f"{flag} needs a git repository, and {target} is not inside one",
                hint="Run inside a repository, or scan without the flag.",
            )

        repository = GitRepository(info.root)

        if args.staged:
            paths = repository.staged_files()
            if not paths:
                # Not an error. A pre-commit hook fires on every commit, including
                # ones that stage nothing this scanner can read, and failing there
                # would teach people to pass --no-verify.
                print("cordon: nothing is staged; no files were scanned", file=sys.stderr)
            return GitIndexSource(repository, paths)

        if args.tracked:
            return GitPathSource(repository.tracked_files(), mode="tracked")

        try:
            changed = repository.changed_files(args.git_diff)
        except SourceError as exc:
            # A ref that does not exist is the user's mistake, not a bug in
            # cordon, and the exit code has to say which. SourceError carries 2,
            # meaning "report this to the maintainers"; a typed ref belongs in 3,
            # meaning "fix your invocation".
            raise ConfigError(
                f"--git-diff: {exc.message}",
                hint=f"Check that {args.git_diff!r} names a commit this repository has.",
            ) from exc
        return GitPathSource(changed, mode=f"diff vs {args.git_diff}", empty_is_normal=True)


__all__ = ["GitModes"]
