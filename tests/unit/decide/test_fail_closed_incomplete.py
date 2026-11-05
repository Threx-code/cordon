"""A scan whose content stopped its reading blocks, whatever `fail_on_incomplete` says; a gap
the machine, a tool or the operator's own scope opened is reported and blocks only with the flag;
stale intel never blocks; and the only way past a content gap is one accepted for that file by the
operator, never by the scanned content (item 27; design note 27-fail-closed-incompleteness.md)."""

from __future__ import annotations

import dataclasses
import errno
import io
import os
import tarfile
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.units import Units
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.foundation.files.walk import WalkError, WalkStats
from cordon_scanner.foundation.models import Suppression
from cordon_scanner.foundation.results import NOT_CONTENT_GAPS, OperationalFinding, ScanResult

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


class TestByCause:
    """Item 27's causes are named by what caused them, never by a message's words, and a cause is
    the machine's only when it is positively known to be (outer-layer review of C5)."""

    def test_a_path_past_max_path_bytes_blocks(self, tmp_path) -> None:
        """On 5351cd0b: content_complete False, content_gaps [], exit 0 under the default policy --
        the file never read and the scan passed. The limit is lowered because the default, 4096,
        is the OS's own: no longer path can be made at it. The cause's class is the same."""
        root = tmp_path / "repo"
        deep = root / ("d" * 60) / ("e" * 60) / ("f" * 60) / ("g" * 60)  # 254 bytes with the file
        deep.mkdir(parents=True)
        (root / "package.json").write_text('{"name": "x", "version": "1.0.0"}', encoding="utf-8")
        (deep / "payload.js").write_text("module.exports = 1;\n", encoding="utf-8")
        config = Config.default().with_overrides(
            use_cache=False,
            offline=True,
            limits=Config.default().limits.merged(max_path_bytes=200),
        )
        result = Scanner(config).scan(root)
        assert any(rule == "OPERATIONAL.WALK.SHAPE" for rule, _ in result.content_gaps)
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE

    @pytest.mark.parametrize("name", sorted(errno.errorcode.values()))
    def test_every_errno_is_the_machine_s_only_when_named(self, name: str) -> None:
        error = WalkError("p", "any words at all", name)
        assert error.the_machines is (name in WalkError.MACHINE)

    @pytest.mark.parametrize(
        "cause", ["ENAMETOOLONG", "ELOOP", WalkError.PATH_TOO_LONG, WalkError.UNKNOWN, "ENEWTHING"]
    )
    def test_the_tree_s_shape_and_anything_unknown_is_the_content_s(self, cause: str) -> None:
        assert not WalkError("p", "", cause).the_machines

    def test_an_oserror_is_named_by_its_errno_not_its_words(self) -> None:
        worded = OSError(errno.ENAMETOOLONG, "a platform's own words for it")
        assert WalkError.of("p", worded).cause == "ENAMETOOLONG"
        assert WalkError.of("p", OSError("no errno")).cause == WalkError.UNKNOWN

    def test_a_cause_nobody_listed_blocks(self) -> None:
        acc = Accumulator()
        acc.incomplete(
            OperationalFinding.build(
                path="a", rule_id="OPERATIONAL.SOMETHING.NEW", message="m", remediation="r"
            )
        )
        assert acc.content_gaps == [("OPERATIONAL.SOMETHING.NEW", "a")]

    @pytest.mark.parametrize("rule", sorted(NOT_CONTENT_GAPS))
    def test_a_named_non_content_cause_does_not(self, rule: str) -> None:
        acc = Accumulator()
        acc.incomplete(
            OperationalFinding.build(path="a", rule_id=rule, message="m", remediation="r")
        )
        assert acc.content_gaps == [] and not acc.complete

    def test_one_finding_is_one_gap(self) -> None:
        """FORMAT.UNREADABLE is reported-incomplete as well: recorded by `incomplete` and again by
        `append`, it was listed twice for one finding."""
        acc = Accumulator()
        acc.incomplete(
            OperationalFinding.build(
                path="a.bin", rule_id="OPERATIONAL.FORMAT.UNREADABLE", message="m", remediation="r"
            )
        )
        assert acc.content_gaps == [("OPERATIONAL.FORMAT.UNREADABLE", "a.bin")]


class TestUnreadBytesBlock:
    """Whether a gap may pass is "is any byte of the package unread?", never "whose fault is it?":
    a machine's cause can be provoked (cordon-47's rule under the owner's decision, 1 Nov)."""

    @staticmethod
    def gate(errors: list[WalkError], policy: Policy) -> ExitCode:
        acc = Accumulator()
        engine = SimpleNamespace(config=Config.default())
        Units.depth_and_errors(engine, SimpleNamespace(stats=WalkStats(errors=errors)), acc)
        coverage = acc.coverage()
        result = ScanResult(
            complete=coverage["complete"],
            content_complete=coverage["content_complete"],
            content_gaps=tuple(coverage["content_gaps"]),
            findings=tuple(acc.findings),
        )
        return PolicyGate.evaluate(result, policy).exit_code

    @pytest.mark.parametrize("name", sorted(WalkError.MACHINE))
    def test_each_machine_cause_blocks_and_passes_only_accepted_for_its_path(
        self, name: str
    ) -> None:
        errors = [WalkError("vendor/hidden", "words", name), WalkError("other/dir", "words", name)]
        assert self.gate(errors, Policy.default()) is ExitCode.INCOMPLETE
        one = dataclasses.replace(
            Policy.default(),
            accepted_gaps=(FailClosedKit.accepted("OPERATIONAL.WALK.ERROR", "vendor/hidden"),),
        )
        assert self.gate(errors, one) is ExitCode.INCOMPLETE  # the other path is still unread
        both = dataclasses.replace(
            one,
            accepted_gaps=(
                *one.accepted_gaps,
                FailClosedKit.accepted("OPERATIONAL.WALK.ERROR", "other/dir"),
            ),
        )
        assert self.gate(errors, both) is ExitCode.CLEAN

    def test_a_directory_nobody_can_list_blocks(self, tmp_path) -> None:
        """A mode-000 directory in a tree: os.walk skipped it with nothing said, so its files were
        neither read nor reported and the scan passed."""
        root = tmp_path / "repo"
        hidden = root / "hidden"
        hidden.mkdir(parents=True)
        (root / "package.json").write_text('{"name": "x", "version": "1.0.0"}', encoding="utf-8")
        (hidden / "payload.js").write_text("module.exports = 1;\n", encoding="utf-8")
        hidden.chmod(0)
        try:
            if os.access(hidden, os.R_OK):
                pytest.skip("this user reads a mode-000 directory (root with CAP_DAC_OVERRIDE)")
            result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
                root
            )
        finally:
            hidden.chmod(0o755)
        assert ("OPERATIONAL.WALK.ERROR", "hidden") in result.content_gaps
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE

    @staticmethod
    def tree_with_archive(tmp_path, *, nested: bool = False):
        """A tree holding vendor.tgz, whose one member is x.js, or with `nested` an inner.tgz
        holding x.js."""
        root = tmp_path / "repo"
        root.mkdir()

        def tgz(members: dict[str, bytes]) -> bytes:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            return buf.getvalue()

        inner = {"x.js": b"1\n"}
        members = {"inner.tgz": tgz(inner)} if nested else inner
        (root / "vendor.tgz").write_bytes(tgz(members))
        return root

    def test_no_expand_is_the_operator_s_choice_named_and_passing(self, tmp_path) -> None:
        """The operator's own coverage choice, which no package can make (a discovered config's
        `expand_archives: false` is clamped): reported incomplete, every archive named, and it
        blocks only with the flag (cordon-47, 1 Nov)."""
        root = self.tree_with_archive(tmp_path)
        config = Config.default().with_overrides(
            use_cache=False, offline=True, expand_archives=False
        )
        result = Scanner(config).scan(root)
        named = [f for f in result.findings if f.rule_id == "OPERATIONAL.ARCHIVE.NOT_EXPANDED"]
        assert named and "vendor.tgz" in named[0].message
        assert not result.content_complete and result.content_gaps == ()
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.CLEAN
        flagged = dataclasses.replace(Policy.default(), fail_on_incomplete=True)
        assert PolicyGate.evaluate(result, flagged).exit_code is ExitCode.INCOMPLETE

    def test_an_archive_a_limit_left_unread_blocks(self, tmp_path) -> None:
        """The package's doing: an archive nested past max_archive_depth (0 here: vendor.tgz is read,
        its inner.tgz is past the limit)."""
        root = self.tree_with_archive(tmp_path, nested=True)
        config = Config.default().with_overrides(
            use_cache=False,
            offline=True,
            limits=Config.default().limits.merged(max_archive_depth=0),
        )
        result = Scanner(config).scan(root)
        assert (
            "OPERATIONAL.ARCHIVE.MEMBER_REJECTED",
            "vendor.tgz!inner.tgz",
        ) in result.content_gaps
        # blocked: by its nesting finding first (the gate reads findings before gaps), and by the
        # gap with no finding to say it
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is not ExitCode.CLEAN
        quiet = dataclasses.replace(result, findings=())
        assert PolicyGate.evaluate(quiet, Policy.default()).exit_code is ExitCode.INCOMPLETE
