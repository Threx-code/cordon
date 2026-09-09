"""The append-only record of what each scan did.

A report says what a scan found. An audit log says a scan happened, under which
rules, and what it was told to ignore -- and that last part cannot come from a
report, because a suppressed finding is by definition absent from one.

Two properties matter more than the format, and both are about what must not be
written: never file content, and never an unredacted remote.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.audit import AuditLog
from cordon_scanner.core.config import Config
from cordon_scanner.core.errors import ConfigError
from support import assemble

PAYLOAD = 'eval(atob("cGF5bG9hZA=="))\n'
TOKEN = assemble("ghp_", "kR9mT2nQ8vL4xW7yZ3bC6dF1gH5jK0pS9rT2")
FUTURE = (date.today() + timedelta(days=60)).isoformat()


def repository(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "evil.js").write_text(PAYLOAD, encoding="utf-8")
    (root / "clean.js").write_text("const a = 1;\n", encoding="utf-8")
    return root


def scan(root: Path):
    return Scanner(Config.default().with_overrides(use_cache=False)).scan(root)


class TestWhatItRecords:
    def entry(self, tmp_path: Path) -> dict:
        root = repository(tmp_path / "repo")
        log = AuditLog.prepare(tmp_path / "audit.jsonl")
        log.record(scan(root), exit_code=1, target_kind="directory")
        return json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())

    def test_it_identifies_the_rules_that_ran(self, tmp_path: Path) -> None:
        """A record that cannot say which rule pack produced it cannot be
        compared with any other record."""
        entry = self.entry(tmp_path)
        assert entry["rulepack_sha256"]
        assert entry["config_sha256"]
        assert entry["cordon_version"]

    def test_it_counts_findings_by_severity(self, tmp_path: Path) -> None:
        entry = self.entry(tmp_path)
        assert entry["findings"]["high"] >= 1
        assert set(entry["findings"]) >= {"critical", "high", "medium", "low", "suppressed"}

    def test_it_records_completeness_and_exit_code(self, tmp_path: Path) -> None:
        """Whether the scan finished is the difference between "clean" and "did
        not look", and an audit record without it cannot tell them apart."""
        entry = self.entry(tmp_path)
        assert entry["complete"] is True
        assert entry["exit_code"] == 1

    def test_one_line_per_scan(self, tmp_path: Path) -> None:
        root = repository(tmp_path / "repo")
        log = AuditLog.prepare(tmp_path / "audit.jsonl")
        for _ in range(3):
            log.record(scan(root), exit_code=1, target_kind="directory")
        lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        assert all(json.loads(line)["event"] == "scan.complete" for line in lines)


class TestWhatItMustNotRecord:
    def test_no_file_content_reaches_it(self, tmp_path: Path) -> None:
        """An audit log is retained longer and read by more people than a
        report, so it is the worst place for the value a secrets rule found."""
        root = tmp_path / "repo"
        root.mkdir()
        (root / "config.py").write_text(f'AWS_SECRET_KEY = "{TOKEN}"\n', encoding="utf-8")
        log = AuditLog.prepare(tmp_path / "audit.jsonl")
        log.record(scan(root), exit_code=1, target_kind="directory")

        written = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert TOKEN not in written
        assert "AWS_SECRET_KEY" not in written

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
    def test_a_credential_in_the_remote_is_not_written(self, tmp_path: Path) -> None:
        """`https://x-access-token:<token>@github.com/org/repo.git` is what
        every CI checkout looks like. Writing it verbatim would make the audit
        log the credential store."""
        root = repository(tmp_path / "repo")
        for command in (
            ["init", "-q", "-b", "main"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "T"],
            ["remote", "add", "origin", f"https://x-access-token:{TOKEN}@github.com/a/b.git"],
            ["add", "-A"],
            ["commit", "-qm", "init"],
        ):
            subprocess.run(
                [shutil.which("git"), *command], cwd=root, check=True, capture_output=True
            )

        log = AuditLog.prepare(tmp_path / "audit.jsonl")
        log.record(scan(root), exit_code=1, target_kind="directory")
        written = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

        assert TOKEN not in written
        entry = json.loads(written.strip())
        assert entry["repo"] == "https://github.com/a/b.git"
        assert entry["revision"], "the commit is what makes the record actionable"


class TestSuppressionsAreTheAuditableFact:
    """An auditor's first question is what the tool was told to ignore."""

    def configured(self, tmp_path: Path) -> Path:
        root = repository(tmp_path / "repo")
        (root / "cordon.yaml").write_text(
            "suppressions:\n"
            "  - rule: SUSPECT.DECODE_EXEC.001\n"
            "    path: evil.js\n"
            "    justification: reviewed by the security team on the 3rd, known loader\n"
            f"    expires: {FUTURE}\n"
            "    approved_by: security-team\n",
            encoding="utf-8",
        )
        return root

    def test_a_suppressed_finding_is_named_with_its_reason(self, tmp_path: Path) -> None:
        from cordon_scanner.core.config import ConfigResolver

        root = self.configured(tmp_path)
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        result = Scanner(config).scan(root)

        log = AuditLog.prepare(tmp_path / "audit.jsonl")
        log.record(result, exit_code=0, target_kind="directory")
        entry = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())

        applied = entry["suppressions_applied"]
        assert applied, "a suppression that appears nowhere is a suppression nobody can review"
        assert applied[0]["rule"] == "SUSPECT.DECODE_EXEC.001"
        assert applied[0]["approved_by"] == "security-team"
        assert applied[0]["expires"] == FUTURE
        assert "security team" in applied[0]["justification"]
        assert entry["findings"]["suppressed"] >= 1

    def test_the_list_is_bounded_and_says_when_it_truncated(self, tmp_path: Path) -> None:
        """A repository can declare an unbounded number, and a log it can grow
        without limit is a disk-exhaustion primitive against the collector."""
        assert AuditLog.MAX_SUPPRESSIONS > 0
        log = AuditLog.prepare(tmp_path / "audit.jsonl")
        entry = log.entry(scan(repository(tmp_path / "repo")), exit_code=0, target_kind="directory")
        assert "suppressions_truncated" in entry


class TestItFailsBeforeTheWork:
    def test_an_unwritable_path_is_refused_up_front(self, tmp_path: Path) -> None:
        """A log that turns out to be unwritable once the scan is done leaves an
        operator with a result they cannot attest to."""
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ConfigError, match="cannot be written"):
            AuditLog.prepare(blocker / "audit.jsonl")

    def test_the_cli_refuses_before_scanning(self, tmp_path: Path) -> None:
        root = repository(tmp_path / "repo")
        blocker = tmp_path / "blocker"
        blocker.write_text("x", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(root),
                "--audit-log",
                str(blocker / "a.jsonl"),
                "--no-cache",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 3, result.stderr
        assert "audit log" in result.stderr


class TestProvenanceReachesTheReport:
    """`Repository.revision` and `remote` were declared, serialised, and never
    set -- so every report recorded `null` for the two fields that say *which*
    code was examined. A result nobody can tie to a commit says a repository
    was clean without saying which version of it."""

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
    def test_a_scan_of_a_repository_records_its_commit(self, tmp_path: Path) -> None:
        root = repository(tmp_path / "repo")
        for command in (
            ["init", "-q", "-b", "main"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "T"],
            ["add", "-A"],
            ["commit", "-qm", "init"],
        ):
            subprocess.run(
                [shutil.which("git"), *command], cwd=root, check=True, capture_output=True
            )
        result = scan(root)
        assert result.repository is not None
        assert result.repository.revision, "the report cannot say which commit it examined"

    def test_a_plain_directory_records_no_commit_and_is_not_an_error(self, tmp_path: Path) -> None:
        """Not a repository is the ordinary case, not a degraded scan."""
        result = scan(repository(tmp_path / "plain"))
        assert result.repository is not None
        assert result.repository.revision is None
        assert result.complete
