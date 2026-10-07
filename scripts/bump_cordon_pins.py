#!/usr/bin/env python3
"""Move every pin of Cordon in a repository to one release (advanced gap E4).

Repositories pin the scanner exactly -- the Action by commit, pip by version and hash, pre-commit
by rev, the runner image by digest -- which is right, and means that when a fix ships every
repository needs the same four edits. This makes them, and only them:

    uses: <owner>/cordon/action@<40 hex>  # vX.Y.Z      -> the release's commit and tag
    cordon-scanner==X.Y.Z  [--hash=sha256:...]          -> the release's version and wheel hashes
    rev: <tag or sha>   under the cordon repo in .pre-commit-config.yaml
    ghcr.io/<owner>/cordon-runner[:tag]@sha256:<digest> -> the release's runner digest

Run by the scheduled workflow in `ci/github/cordon-pin-bump.yml`, once per repository, before it
opens the pull request. Prints what it changed; exits 1 when it changed something, 0 when the
repository was already current.

    python scripts/bump_cordon_pins.py REPO_DIR --version 0.5.3 --commit <sha> \\
        --wheel-sha256 <hex> [--wheel-sha256 <hex>] [--runner-digest sha256:<hex>]
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

#: The files a pin can live in. Nothing else is opened, so a match in a README or a test fixture
#: is never rewritten.
PIN_FILES = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".github/actions/*/action.yml",
    ".pre-commit-config.yaml",
    "requirements*.txt",
    "**/requirements*.txt",
    ".gitlab-ci.yml",
    "Dockerfile",
    "**/Dockerfile",
    "bitbucket-pipelines.yml",
    "azure-pipelines.yml",
    ".circleci/config.yml",
    ".buildkite/pipeline.yml",
    "Jenkinsfile",
)
MAX_FILE_BYTES = 1 << 20


@dataclass(frozen=True)
class Release:
    version: str
    commit: str
    wheel_hashes: tuple[str, ...] = ()
    runner_digest: str | None = None


@dataclass
class Bump:
    """What changed in one file."""

    path: str
    changes: list[str] = field(default_factory=list)


class CordonPins:
    ACTION = re.compile(
        r"(?P<head>uses:\s*['\"]?[\w.-]+/cordon/action@)(?P<sha>[0-9a-f]{40})(?P<quote>['\"]?)(?P<comment>[ \t]*#[ \t]*v?[\w.+-]*)?"
    )
    PIP = re.compile(r"(?P<head>\bcordon-scanner==)(?P<version>\d+\.\d+\.\d+(?:[ab]\d+)?)")
    HASH_LINE = re.compile(r"^(?P<indent>[ \t]+)--hash=sha256:[0-9a-f]{64}(?P<tail>[ \t]*\\?)$")
    RUNNER = re.compile(
        r"(?P<head>ghcr\.io/[\w.-]+/cordon-runner(?::[\w.-]+)?@)(?P<digest>sha256:[0-9a-f]{64})"
    )
    PRE_COMMIT_REPO = re.compile(r"^\s*-\s*repo:\s*\S*/cordon(?:\.git)?\s*$")
    PRE_COMMIT_REV = re.compile(
        r"^(?P<head>\s*rev:\s*['\"]?)(?P<rev>[\w.+-]+)(?P<tail>['\"]?\s*(?:#.*)?)$"
    )

    @staticmethod
    def bump(path: str, text: str, release: Release) -> tuple[str, Bump]:
        bump = Bump(path)
        tag = f"v{release.version}"

        def action(match: re.Match[str]) -> str:
            if match.group("sha") == release.commit:
                return match.group(0)
            bump.changes.append(
                f"action {match.group('sha')[:12]} -> {release.commit[:12]} ({tag})"
            )
            return f"{match.group('head')}{release.commit}{match.group('quote')}  # {tag}"

        text = CordonPins.ACTION.sub(action, text)

        def runner(match: re.Match[str]) -> str:
            if release.runner_digest is None or match.group("digest") == release.runner_digest:
                return match.group(0)
            bump.changes.append(
                f"runner image {match.group('digest')[:19]} -> {release.runner_digest[:19]}"
            )
            return f"{match.group('head')}{release.runner_digest}"

        text = CordonPins.RUNNER.sub(runner, text)
        text = CordonPins._pip(text, release, bump)
        if path.endswith(".pre-commit-config.yaml"):
            text = CordonPins._pre_commit(text, tag, bump)
        return text, bump

    @staticmethod
    def _pip(text: str, release: Release, bump: Bump) -> str:
        """`cordon-scanner==X` and, where the pin is hash-checked, the `--hash` lines under it."""
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            match = CordonPins.PIP.search(line)
            if not match or (
                match.group("version") == release.version and not release.wheel_hashes
            ):
                out.append(line)
                index += 1
                continue
            if match.group("version") != release.version:
                bump.changes.append(f"cordon-scanner {match.group('version')} -> {release.version}")
            out.append(
                line[: match.start("version")] + release.version + line[match.end("version") :]
            )
            index += 1
            hashes: list[str] = []
            while index < len(lines) and CordonPins.HASH_LINE.match(lines[index].rstrip("\n")):
                hashes.append(lines[index])
                index += 1
            if hashes and release.wheel_hashes:
                indent = CordonPins.HASH_LINE.match(hashes[0].rstrip("\n"))
                prefix = indent.group("indent") if indent else "    "
                rendered = [
                    f"{prefix}--hash=sha256:{digest}"
                    + (" \\" if n < len(release.wheel_hashes) - 1 else "")
                    + "\n"
                    for n, digest in enumerate(release.wheel_hashes)
                ]
                if rendered != hashes:
                    bump.changes.append(f"cordon-scanner hashes ({len(release.wheel_hashes)})")
                out += rendered
            else:
                out += hashes
        return "".join(out)

    @staticmethod
    def _pre_commit(text: str, tag: str, bump: Bump) -> str:
        lines = text.splitlines(keepends=True)
        inside = False
        for number, line in enumerate(lines):
            if line.lstrip().startswith("- repo:"):
                inside = bool(CordonPins.PRE_COMMIT_REPO.match(line.rstrip("\n")))
                continue
            match = CordonPins.PRE_COMMIT_REV.match(line.rstrip("\n")) if inside else None
            if match and match.group("rev") != tag:
                bump.changes.append(f"pre-commit rev {match.group('rev')} -> {tag}")
                lines[number] = f"{match.group('head')}{tag}{match.group('tail')}\n"
                inside = False
        return "".join(lines)

    @staticmethod
    def run(root: Path, release: Release) -> list[Bump]:
        bumps: list[Bump] = []
        seen: set[Path] = set()
        for pattern in PIN_FILES:
            for path in sorted(root.glob(pattern)):
                if (
                    path in seen
                    or not path.is_file()
                    or path.is_symlink()
                    or path.stat().st_size > MAX_FILE_BYTES
                ):
                    continue
                seen.add(path)
                text = path.read_text(encoding="utf-8")
                updated, bump = CordonPins.bump(path.relative_to(root).as_posix(), text, release)
                if updated != text:
                    path.write_text(updated, encoding="utf-8")
                    bumps.append(bump)
        return bumps


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("root", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--wheel-sha256", action="append", default=[])
    parser.add_argument("--runner-digest", default=None)
    arguments = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.commit) or not re.fullmatch(
        r"\d+\.\d+\.\d+(?:[ab]\d+)?", arguments.version
    ):
        sys.exit("--commit must be a 40-character commit id and --version a release number")
    if any(not re.fullmatch(r"[0-9a-f]{64}", h) for h in arguments.wheel_sha256):
        sys.exit("--wheel-sha256 takes 64 hex characters")
    changed = CordonPins.run(
        arguments.root,
        Release(
            arguments.version,
            arguments.commit,
            tuple(arguments.wheel_sha256),
            arguments.runner_digest,
        ),
    )
    for bump in changed:
        print(f"{bump.path}: {'; '.join(bump.changes)}")
    sys.exit(1 if changed else 0)
