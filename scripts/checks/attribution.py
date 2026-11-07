#!/usr/bin/env python3
"""No co-author or tool-attribution line in a commit message or a pull request (owner's rule).

A commit or PR names no co-author and credits no tool: no `Co-Authored-By:` trailer of any kind,
no "Generated with ..." footer, no assistant's noreply address. Tools that write commits add these
lines by default, so the rule is enforced here rather than remembered.

    python scripts/checks/attribution.py --message .git/COMMIT_EDITMSG   # the commit-msg hook
    python scripts/checks/attribution.py --commits origin/main..HEAD     # every commit in a range
    python scripts/checks/attribution.py --text "$PR_BODY"               # a PR title or body

Exit 1 with each offending line on any finding, 0 otherwise. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

#: Each pattern names a line no commit or PR may carry. Matched per line, case-insensitively.
FORBIDDEN: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("co-author trailer", re.compile(r"(?i)^\s*co-?authored-?by\s*:")),
    (
        "tool attribution",
        re.compile(
            r"(?i)\bgenerated\s+(?:with|by)\s+\[?\s*(?:claude|copilot|chatgpt|codex|cursor|gemini)"
        ),
    ),
    ("assistant address", re.compile(r"(?i)\bnoreply@anthropic\.com\b|\bnoreply@openai\.com\b")),
)


class Attribution:
    """Finds the forbidden lines in commit messages and pull request text."""

    @staticmethod
    def findings(text: str) -> Iterator[tuple[str, str]]:
        """(what, line) for every forbidden line in `text`; git's own comment lines are skipped."""
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            for what, pattern in FORBIDDEN:
                if pattern.search(line):
                    yield what, line.strip()
                    break

    @staticmethod
    def commits(revisions: str) -> Iterator[tuple[str, str]]:
        """(sha, message) for every commit in a revision range."""
        out = subprocess.run(  # noqa: S603 - a fixed git verb; the range is the caller's
            ["git", "log", "--format=%H%x00%B%x01", revisions],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout
        for record in out.split("\x01"):
            sha, _, message = record.strip("\n").partition("\x00")
            if sha:
                yield sha, message

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        ap = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        source = ap.add_mutually_exclusive_group(required=True)
        source.add_argument(
            "--message", help="a commit message file (the commit-msg hook's argument)"
        )
        source.add_argument("--commits", help="a git revision range, e.g. origin/main..HEAD")
        source.add_argument("--text", help="text to check, e.g. a pull request's title and body")
        args = ap.parse_args(argv)

        if args.message is not None:
            checked = [("this commit", Path(args.message).read_text(encoding="utf-8"))]
        elif args.commits is not None:
            checked = [(sha[:12], message) for sha, message in Attribution.commits(args.commits)]
        else:
            checked = [("the pull request", args.text)]

        bad = [
            (where, what, line)
            for where, text in checked
            for what, line in Attribution.findings(text)
        ]
        for where, what, line in bad:
            print(f"{where}: {what}: {line}", file=sys.stderr)
        if bad:
            print(
                "No co-author or attribution lines in commits or PRs: remove them "
                "(git commit --amend, or reword before pushing).",
                file=sys.stderr,
            )
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(Attribution.main())
