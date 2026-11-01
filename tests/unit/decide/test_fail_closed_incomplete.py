"""A scan whose content stopped its reading blocks, whatever `fail_on_incomplete` says; a gap
the machine, a tool or the operator's own scope opened is reported and blocks only with the flag;
stale intel never blocks; and the only way past a content gap is one accepted for that file by the
operator, never by the scanned content (item 27; design note 27-fail-closed-incompleteness.md)."""

from __future__ import annotations

import dataclasses
import io
import tarfile
from datetime import date, timedelta

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.foundation.models import Suppression
from cordon_scanner.foundation.results import ScanResult

GAP = ("OPERATIONAL.ARCHIVE.MEMBER_REJECTED", "pkg-1.0.tar.gz!pkg/inner.tgz")


class FailClosedKit:
    @staticmethod
    def accepted(rule: str, path: str, *, days: int = 30) -> Suppression:
        return Suppression(
            rule=rule,
            path=path,
            justification="a zip library's own deliberately broken test fixture",
            expires=(date.today() + timedelta(days=days)).isoformat(),
            approved_by="security@example.org",
        )

    @staticmethod
    def corrupt_member_sdist(tmp_path):
        """A package whose nested archive does not open: its content left unread by its own bytes."""
        path = tmp_path / "pkg-1.0.tar.gz"
        inner = b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"not a deflate stream at all"
        with tarfile.open(path, "w:gz") as tar:
            for name, data in (("pkg/inner.tgz", inner), ("pkg/README.md", b"hello\n")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path


class TestTheGate:
    def test_a_content_gap_blocks_without_the_flag(self) -> None:
        result = ScanResult(complete=False, content_complete=False, content_gaps=(GAP,))
        verdict = PolicyGate.evaluate(result, Policy.default())
        assert verdict.exit_code is ExitCode.INCOMPLETE
        assert GAP[0] in verdict.reason

    def test_any_other_gap_blocks_only_with_the_flag(self) -> None:
        result = ScanResult(complete=False, content_complete=False)
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.CLEAN
        flagged = dataclasses.replace(Policy.default(), fail_on_incomplete=True)
        assert PolicyGate.evaluate(result, flagged).exit_code is ExitCode.INCOMPLETE

    def test_stale_intel_never_blocks(self) -> None:
        result = ScanResult(complete=False, content_complete=True, advisory_complete=False)
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.CLEAN

    def test_an_accepted_gap_passes_and_an_expired_one_does_not(self) -> None:
        result = ScanResult(complete=False, content_complete=False, content_gaps=(GAP,))
        accepted = dataclasses.replace(
            Policy.default(), accepted_gaps=(FailClosedKit.accepted(*GAP),)
        )
        assert PolicyGate.evaluate(result, accepted).exit_code is ExitCode.CLEAN
        expired = dataclasses.replace(
            Policy.default(), accepted_gaps=(FailClosedKit.accepted(*GAP, days=-1),)
        )
        assert PolicyGate.evaluate(result, expired).exit_code is ExitCode.INCOMPLETE

    def test_an_acceptance_covers_its_file_alone(self) -> None:
        other = ("OPERATIONAL.ARCHIVE.MEMBER_REJECTED", "pkg-1.0.tar.gz!pkg/other.tgz")
        result = ScanResult(complete=False, content_complete=False, content_gaps=(GAP, other))
        accepted = dataclasses.replace(
            Policy.default(), accepted_gaps=(FailClosedKit.accepted(*GAP),)
        )
        assert PolicyGate.evaluate(result, accepted).exit_code is ExitCode.INCOMPLETE


class TestInAScan:
    def test_an_archive_that_does_not_open_blocks(self, tmp_path) -> None:
        """Today: complete False, and a pass (exit 0) without the flag."""
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            FailClosedKit.corrupt_member_sdist(tmp_path)
        )
        assert any(rule == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" for rule, _ in result.content_gaps)
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE

    def test_a_package_cannot_accept_its_own_gap(self, tmp_path) -> None:
        """An acceptance in a cordon.yaml inside the scanned tree is withheld."""
        (tmp_path / "cordon.yaml").write_text(
            "policy:\n"
            "  accepted_gaps:\n"
            "    - rule: OPERATIONAL.ARCHIVE.MEMBER_REJECTED\n"
            "      path: '**'\n"
            "      justification: trust me, this archive is fine to leave unread\n"
            "      approved_by: me\n"
            f"      expires: '{(date.today() + timedelta(days=30)).isoformat()}'\n",
            encoding="utf-8",
        )
        discovered = Config.discover(tmp_path)
        assert discovered.policy.accepted_gaps is not None  # read, as written
        assert discovered._withhold_untrusted_powers().policy.accepted_gaps is None
