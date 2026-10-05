"""G11: secrets in git history, and the opt-in issuer check.

A real repository is built in a temporary directory for every history test: a credential is
committed, then deleted, and the pass must find it in history at the commit that introduced it.
The token is assembled at run time so no credential-shaped literal lives in this file. No test
reaches an issuer: the opener is replaced, and the tests assert what would have been sent where.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Evidence
from cordon_scanner.detect.secret_history import (
    HISTORY_INCOMPLETE_RULE,
    LIVE_RULE,
    REVOKED_RULE,
    UNCHECKED_RULE,
    HistorySecretScan,
    SecretLiveness,
    SecretValues,
)
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.sources.git import GitRepository
from cordon_scanner.sources.history import GitHistory

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class HistoryKit:
    @staticmethod
    def token(seed: str) -> str:
        digest = hashlib.sha256(seed.encode()).digest() * 2
        return "ghp_" + "".join(ALPHABET[b % 62] for b in digest[:36])

    @staticmethod
    def git(root: Path, *args: str) -> str:
        return subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@example.test",
                "-c",
                "user.name=t",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    @classmethod
    def repository(cls, root: Path, token: str) -> str:
        root.mkdir(parents=True, exist_ok=True)
        cls.git(root, "init", "-q", "-b", "main")
        (root / "deploy.py").write_text(f'GITHUB = "{token}"\nprint("deploying")\n')
        (root / "README.md").write_text("demo\n")
        cls.git(root, "add", "-A")
        cls.git(root, "commit", "-q", "-m", "add deploy")
        introduced = cls.git(root, "rev-parse", "HEAD").strip()
        (root / "deploy.py").write_text('GITHUB = os.environ["GITHUB_TOKEN"]\nprint("deploying")\n')
        cls.git(root, "commit", "-q", "-am", "read the token from the environment")
        return introduced

    @staticmethod
    def scan(root: Path) -> HistorySecretScan:
        return HistorySecretScan(root, Config.default(), RuleSet(RuleLoader.load_builtin()))


class TestGitHistory:
    def test_only_blobs_missing_from_the_tree_are_read(self, tmp_path) -> None:
        HistoryKit.repository(tmp_path, HistoryKit.token("a"))
        history = GitHistory(GitRepository(tmp_path))
        blobs = list(history.blobs())
        assert [b.path for b in blobs] == ["deploy.py"]
        assert b"ghp_" in blobs[0].data
        assert history.coverage.complete and history.coverage.read == 1

    def test_the_introducing_commit_is_found(self, tmp_path) -> None:
        introduced = HistoryKit.repository(tmp_path, HistoryKit.token("b"))
        history = GitHistory(GitRepository(tmp_path))
        (blob,) = list(history.blobs())
        commit, when = history.introduced_by(blob.object_id) or ("", "")
        assert commit == introduced and when[:4].isdigit()

    def test_bounds_are_counted_not_silent(self, tmp_path) -> None:
        HistoryKit.repository(tmp_path, HistoryKit.token("c"))
        small = GitHistory(GitRepository(tmp_path), max_blob_bytes=10)
        assert (
            list(small.blobs()) == []
            and small.coverage.skipped_large == 1
            and not small.coverage.complete
        )
        capped = GitHistory(GitRepository(tmp_path), max_blobs=0)
        assert list(capped.blobs()) == [] and capped.coverage.skipped_over_ceiling == 1

    def test_the_time_budget_stops_the_pass_and_says_so(self, tmp_path) -> None:
        HistoryKit.repository(tmp_path, HistoryKit.token("d"))
        ticks = iter([0.0, 1000.0, 1000.0])
        history = GitHistory(GitRepository(tmp_path), time_budget=1.0, clock=lambda: next(ticks))
        assert list(history.blobs()) == [] and history.coverage.stopped_for_time

    def test_a_repository_with_no_history_beyond_the_tree_reads_nothing(self, tmp_path) -> None:
        tmp_path.mkdir(exist_ok=True)
        HistoryKit.git(tmp_path, "init", "-q")
        (tmp_path / "a.txt").write_text("x\n")
        HistoryKit.git(tmp_path, "add", "-A")
        HistoryKit.git(tmp_path, "commit", "-q", "-m", "one")
        assert list(GitHistory(GitRepository(tmp_path)).blobs()) == []


class TestHistorySecretScan:
    def test_a_deleted_token_is_reported_at_its_commit(self, tmp_path) -> None:
        token = HistoryKit.token("e")
        introduced = HistoryKit.repository(tmp_path, token)
        findings = HistoryKit.scan(tmp_path).run()
        (finding,) = [f for f in findings if f.rule_id == "SECRET.GITHUB.TOKEN.001"]
        assert finding.location.symbol == f"history:{introduced[:12]}"
        assert "still in git history" in finding.message and introduced[:12] in finding.message
        # Keyed per install: a published hash cannot be checked against guesses.
        assert finding.evidence.match_hash == Evidence.secret_hash(token.encode())
        assert finding.evidence.match_hash != Evidence.hash_bytes(token.encode())
        assert token not in json.dumps([f.message for f in findings])

    def test_one_credential_in_many_revisions_is_one_finding(self, tmp_path) -> None:
        token = HistoryKit.token("f")
        HistoryKit.repository(tmp_path, token)
        for n in range(3):
            (tmp_path / "deploy.py").write_text(f'GITHUB = "{token}"\nprint({n})\n')
            HistoryKit.git(tmp_path, "commit", "-q", "-am", f"rev {n}")
        (tmp_path / "deploy.py").write_text("print('clean')\n")
        HistoryKit.git(tmp_path, "commit", "-q", "-am", "clean")
        findings = [
            f for f in HistoryKit.scan(tmp_path).run() if f.rule_id == "SECRET.GITHUB.TOKEN.001"
        ]
        assert len(findings) == 1

    def test_not_a_repository_reads_nothing(self, tmp_path) -> None:
        assert HistoryKit.scan(tmp_path).run() == []

    def test_an_incomplete_pass_reports_itself(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.sources import history

        HistoryKit.repository(tmp_path, HistoryKit.token("g"))
        monkeypatch.setattr(history, "MAX_BLOB_BYTES", 10)
        findings = HistoryKit.scan(tmp_path).run()
        note = [f for f in findings if f.rule_id == HISTORY_INCOMPLETE_RULE]
        assert note and note[0].degrades_coverage

    def test_the_cli_reports_history_and_marks_the_result(self, tmp_path, capsys) -> None:
        token = HistoryKit.token("h")
        HistoryKit.repository(tmp_path, token)
        code = CommandLine.run(
            ["scan", str(tmp_path), "--history", "--format", "json", "--no-color"]
        )
        out = capsys.readouterr().out
        assert code == 1 and token not in out
        report = json.loads(out)
        assert any(f["rule_id"] == "SECRET.GITHUB.TOKEN.001" for f in report["findings"])

    def test_without_the_flag_history_is_not_read(self, tmp_path, capsys) -> None:
        HistoryKit.repository(tmp_path, HistoryKit.token("i"))
        CommandLine.run(["scan", str(tmp_path), "--format", "json", "--no-color"])
        report = json.loads(capsys.readouterr().out)
        assert not any(f["rule_id"].startswith("SECRET.GITHUB") for f in report["findings"])


class TestLiveness:
    @staticmethod
    def finding(tmp_path: Path, token: str, rule: str = "SECRET.GITHUB.TOKEN.001"):
        HistoryKit.repository(tmp_path, token)
        (finding,) = [
            f for f in HistoryKit.scan(tmp_path).run() if f.rule_id == "SECRET.GITHUB.TOKEN.001"
        ]
        return finding

    def test_a_live_token_is_critical_and_was_sent_only_to_its_issuer(self, tmp_path) -> None:
        token = HistoryKit.token("j")
        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, token)
        findings = scan.run()
        sent: list[tuple[str, dict]] = []

        def opener(request):
            sent.append((request.full_url, dict(request.header_items())))
            return 200, b"{}"

        added = SecretLiveness(opener=opener, clock=lambda: 0).verify(
            findings, SecretValues(tmp_path, scan.blob_contents)
        )
        live = [f for f in added if f.rule_id == LIVE_RULE]
        assert live and live[0].severity.name == "CRITICAL"
        assert [url for url, _ in sent] == ["https://api.github.com/user"]
        assert sent[0][1]["Authorization"] == f"Bearer {token}"
        assert token not in json.dumps([f.message for f in added])

    def test_a_rejected_token_is_info(self, tmp_path) -> None:
        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, HistoryKit.token("k"))
        findings = scan.run()
        added = SecretLiveness(opener=lambda r: (401, b"")).verify(
            findings, SecretValues(tmp_path, scan.blob_contents)
        )
        assert [f.rule_id for f in added] == [REVOKED_RULE]

    def test_an_unclear_answer_is_unchecked_not_clean(self, tmp_path) -> None:
        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, HistoryKit.token("l"))
        findings = scan.run()
        added = SecretLiveness(opener=lambda r: (503, b"")).verify(
            findings, SecretValues(tmp_path, scan.blob_contents)
        )
        assert [f.rule_id for f in added] == [UNCHECKED_RULE]

    def test_a_network_failure_is_unchecked(self, tmp_path) -> None:
        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, HistoryKit.token("m"))
        findings = scan.run()

        def down(request):
            raise OSError("unreachable")

        added = SecretLiveness(opener=down).verify(
            findings, SecretValues(tmp_path, scan.blob_contents)
        )
        assert [f.rule_id for f in added] == [UNCHECKED_RULE]

    def test_a_value_that_no_longer_hashes_to_the_finding_is_never_sent(self, tmp_path) -> None:
        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, HistoryKit.token("n"))
        findings = scan.run()
        tampered = {key: b"x" * len(blob) for key, blob in scan.blob_contents.items()}
        sent: list[str] = []
        SecretLiveness(opener=lambda r: (sent.append(r.full_url), (200, b""))[1]).verify(
            findings, SecretValues(tmp_path, tampered)
        )
        assert sent == []

    def test_a_tree_value_outside_the_root_is_refused(self, tmp_path) -> None:
        from dataclasses import replace

        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, HistoryKit.token("o"))
        (finding,) = [f for f in scan.run() if f.rule_id == "SECRET.GITHUB.TOKEN.001"]
        escaped = replace(
            finding,
            location=replace(finding.location, path="../../etc/passwd", symbol=None),
            fingerprint="",
        )
        assert SecretValues(tmp_path)(escaped) is None

    def test_side_effecting_shapes_are_never_checked(self) -> None:
        assert "SECRET.SLACK.WEBHOOK.001" not in SecretLiveness.issuers()
        assert "posting" in SecretLiveness.NOT_CHECKABLE["SECRET.SLACK.WEBHOOK.001"]

    def test_every_issuer_sends_only_to_its_own_https_host(self) -> None:
        for rule_id, issuer in SecretLiveness.issuers().items():
            request = issuer.request("value")
            assert request.full_url.startswith(f"https://{issuer.host}/"), rule_id

    @pytest.mark.parametrize(
        "body, verdict",
        [
            (b'{"ok": true}', True),
            (b'{"ok": false, "error": "invalid_auth"}', False),
            (b'{"ok": false, "error": "ratelimited"}', None),
            (b"<html>", None),
        ],
    )
    def test_slack_answers_are_read_by_their_body(self, body, verdict) -> None:
        assert SecretLiveness._slack(200, body) is verdict

    def test_the_check_ceiling_is_respected(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.detect import secret_history

        scan = HistoryKit.scan(tmp_path)
        HistoryKit.repository(tmp_path, HistoryKit.token("p"))
        findings = scan.run()
        monkeypatch.setattr(secret_history, "MAX_VERIFICATIONS", 0)
        added = SecretLiveness(opener=lambda r: (200, b"")).verify(
            findings, SecretValues(tmp_path, scan.blob_contents)
        )
        assert [f.rule_id for f in added] == [UNCHECKED_RULE]

    def test_verify_secrets_needs_online(self, tmp_path, capsys) -> None:
        assert CommandLine.run(["scan", str(tmp_path), "--verify-secrets"]) == 3
        assert "--online" in capsys.readouterr().err
