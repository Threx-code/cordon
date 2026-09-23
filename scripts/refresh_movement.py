#!/usr/bin/env python3
"""Decide whether a refresh produced anything worth proposing to a reviewer.

A MAINTENANCE script, used by the three refresh workflows between staging their
output and pushing a branch.

The refreshes write a metadata sidecar carrying `built_at`, and that field moves
on every run whether or not the data did. Staged alongside a digest manifest
that hashes it, it guarantees a non-empty diff, so `git diff --cached --quiet`
can never report "nothing moved" -- and a weekly job that always has something
to say opens a pull request and files an issue every week for a no-op.

Deleting the timestamp is not the answer. `detect/advisory.py` and
`detect/iac.py` both read `built_at` and warn when the data is older than their
freshness window, and the infrastructure one says out loud that "resources added
to a provider since then have no policy at all". After a run that found nothing
to change, that sentence is false: the sources were read and they had not moved.
The stamp is the record of when the data was last confirmed against its sources,
which is exactly what makes the warning honest, so it has to keep moving.

So the question this answers is not "did any byte change" but "is this worth a
person's attention", and there are two ways to be worth it:

`substantive`   the data itself moved, which is a change to review.
`confirmation`  the data is identical, but the stamp on the shipped copy has
                aged past `--confirm-after-days`. Proposed so the recorded
                confirmation is refreshed well before the freshness window it
                feeds would start warning, rather than once a week forever.
`none`          the data is identical and the stamp is recent. Nothing is
                pushed, and no issue is filed.

A refresh with no `--stamp` never reports `confirmation`: with nothing reading
a date, there is no date to keep current, and only the data can be worth
proposing.

The verdict is the only thing on stdout; the reasoning goes to stderr.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import re
import subprocess
import sys


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    # git, on the repository this script is being run inside. The arguments are
    # literals from this file and the workflow that calls it, and resolving git
    # from PATH is the point: it is the runner's own checkout being inspected.
    return subprocess.run(["git", *args], capture_output=True, check=False)  # noqa: S603, S607


def staged_paths() -> list[str]:
    """Every path in the index that differs from HEAD."""
    result = _git("diff", "--cached", "--name-only")
    if result.returncode != 0:
        raise SystemExit(result.stderr.decode("utf-8", "replace").strip())
    return [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line]


def blob(ref: str, path: str) -> bytes | None:
    """A path's bytes at `ref`, or None where it does not exist there.

    `ref` is empty for the index, which is what `git show :path` reads.
    """
    result = _git("show", f"{ref}:{path}")
    return result.stdout if result.returncode == 0 else None


def without(content: bytes, ignore: re.Pattern[str] | None) -> bytes:
    """`content` with the ignorable lines dropped.

    For the allowlist files, whose header records the date they were fetched.
    That line moves daily on its own and says nothing about the names below it.
    """
    if ignore is None:
        return content
    kept = [
        line for line in content.decode("utf-8", "replace").splitlines() if not ignore.search(line)
    ]
    return "\n".join(kept).encode("utf-8")


def data_moved(paths: list[str], globs: list[str], ignore: re.Pattern[str] | None) -> list[str]:
    """The staged data files whose content differs from HEAD's.

    A path that is new or deleted counts as moved: both are changes to the data
    set even though neither has two versions to compare.
    """
    moved = []
    for path in paths:
        if not any(fnmatch.fnmatch(path, glob) for glob in globs):
            continue
        now, was = blob("", path), blob("HEAD", path)
        missing = now is None or was is None
        if missing or without(now or b"", ignore) != without(was or b"", ignore):
            moved.append(path)
    return moved


def stamp_age_days(path: str, field: str) -> float | None:
    """How long ago HEAD's copy of `path` says the data was last confirmed.

    None when there is nothing to read -- no such file at HEAD, or a field that
    is missing or not a timestamp. The caller treats that as due, because a
    stamp that cannot be read is not evidence that the data was confirmed
    recently.
    """
    raw = blob("HEAD", path)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8")).get(field)
        built = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    if built.tzinfo is None:
        built = built.replace(tzinfo=dt.UTC)
    return (dt.datetime.now(dt.UTC) - built).total_seconds() / 86400


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", nargs="+", required=True, metavar="GLOB")
    # Optional: the allowlist refresh has no stamp to keep current. Its files
    # carry a `# Refreshed:` header, but nothing reads it -- it is there for a
    # person opening the file, and no rule warns on its age -- so that refresh
    # is worth proposing when the names move and at no other time.
    parser.add_argument("--stamp", default=None, metavar="PATH")
    parser.add_argument("--stamp-field", default="built_at")
    parser.add_argument("--confirm-after-days", type=float, default=None)
    parser.add_argument("--ignore-line", default=None, metavar="REGEX")
    args = parser.parse_args()

    ignore = re.compile(args.ignore_line) if args.ignore_line else None
    moved = data_moved(staged_paths(), args.data, ignore)
    if moved:
        shown = ", ".join(moved[:5]) + (f" and {len(moved) - 5} more" if len(moved) > 5 else "")
        print(f"data moved: {shown}", file=sys.stderr)
        print("substantive")
        return 0

    if args.stamp is None or args.confirm_after_days is None:
        print("data identical and no stamp to keep current; nothing to propose", file=sys.stderr)
        print("none")
        return 0

    age = stamp_age_days(args.stamp, args.stamp_field)
    if age is None:
        print(f"no readable {args.stamp_field} at HEAD; proposing the refresh", file=sys.stderr)
        print("confirmation")
        return 0
    if age >= args.confirm_after_days:
        print(
            f"data identical; the recorded {args.stamp_field} is {age:.0f} days old, "
            f"past the {args.confirm_after_days:.0f}-day confirmation interval",
            file=sys.stderr,
        )
        print("confirmation")
        return 0

    print(
        f"data identical and confirmed {age:.0f} days ago, inside the "
        f"{args.confirm_after_days:.0f}-day interval; nothing to propose",
        file=sys.stderr,
    )
    print("none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
