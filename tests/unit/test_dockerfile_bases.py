"""Every image this project builds starts from a base pinned by digest.

A tag is mutable: two builds of the same Dockerfile can produce different images. Code scanning
flagged `ci/bitbucket/Dockerfile` on 2026-10-05 for `FROM python:3.12-slim` while the root
Dockerfile was already pinned; this keeps every Dockerfile the project ships to that standard.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: Directories holding samples and fixtures, not images this project builds.
NOT_SHIPPED = ("corpus", "bench", "tests", ".iac-schema", "node_modules", ".git", "build", "dist")


class TestDockerfileBases:
    @staticmethod
    def shipped() -> list[Path]:
        return [
            path
            for path in ROOT.rglob("Dockerfile*")
            if path.is_file() and not set(path.relative_to(ROOT).parts) & set(NOT_SHIPPED)
        ]

    def test_the_shipped_dockerfiles_are_found(self) -> None:
        names = {path.relative_to(ROOT).as_posix() for path in self.shipped()}
        assert {"Dockerfile", "ci/bitbucket/Dockerfile"} <= names

    def test_every_base_is_pinned_by_digest(self) -> None:
        unpinned = [
            f"{path.relative_to(ROOT).as_posix()}: {line.strip()}"
            for path in self.shipped()
            for line in path.read_text(encoding="utf-8").splitlines()
            if re.match(r"^\s*FROM\s", line, re.I) and "@sha256:" not in line
        ]
        assert not unpinned, unpinned
