"""A member name that is not plain text -- a byte that is not UTF-8, a terminal escape, a bidi
override, a line break -- reaches every report as a name, shown escaped, and the scan is graded as
any other (item 34). Not an internal error, not a missing report, and not a way to write control
sequences into a terminal or a pull request."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.registry import BUILTIN_REPORTERS, Registry
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.base import ReportOptions

DECODE = "b64" + "decode"
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
).encode()

# a byte that is not UTF-8 (read back as a lone surrogate), a terminal escape, a bidi override and
# a line break, each in the name of a file holding the planted decode-then-run
NAMES = ("pkg/run\udca7.py", "pkg/\x1b[31mred.py", "pkg/‮yp.txt.py", "pkg/two\nlines.py")
RAW = ("\udca7", "\x1b", "‮")


class UnreadableNamesKit:
    @staticmethod
    def tarball(tmp_path):
        path = tmp_path / "names-1.0.tar"
        with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
            for name in NAMES:
                info = tarfile.TarInfo(name)
                info.size = len(PLANT)
                tar.addfile(info, io.BytesIO(PLANT))
        return path

    @staticmethod
    def zipped(tmp_path):
        # zip names are UTF-8 or cp437, so never a lone surrogate: the other three
        path = tmp_path / "names-1.0.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name in NAMES[1:]:
                archive.writestr(name, PLANT)
        return path

    @staticmethod
    def links(tmp_path):
        """A tar holding two link members, one that stays inside and one that climbs out, each name
        and target with a byte that is not UTF-8 and an escape, beside the file one names."""
        path = tmp_path / "links-1.0.tar"
        with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
            for member, target in (
                ("pkg/in\udca7\x1b", "run.py"),
                ("pkg/out\udca7", "../../\udcfe\x1bx"),
            ):
                info = tarfile.TarInfo(member)
                info.type, info.linkname = tarfile.SYMTYPE, target
                tar.addfile(info)
            info = tarfile.TarInfo("pkg/run.py")
            info.size = len(PLANT)
            tar.addfile(info, io.BytesIO(PLANT))
        return path

    @staticmethod
    def scan(path):
        config = Config.default().with_overrides(use_cache=False)
        return Scanner(config).scan(path)


class TestANameThatIsNotText:
    @pytest.mark.parametrize("make", [UnreadableNamesKit.tarball, UnreadableNamesKit.zipped])
    def test_every_member_is_scanned_and_graded(self, tmp_path, make) -> None:
        result = UnreadableNamesKit.scan(make(tmp_path))
        planted = {
            f.location.path for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"
        }
        assert len(planted) == (
            len(NAMES) if make is UnreadableNamesKit.tarball else len(NAMES) - 1
        )

    def test_a_line_break_in_a_name_cannot_start_a_workflow_command(self, tmp_path) -> None:
        path = tmp_path / "inject-1.0.tar"
        with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
            info = tarfile.TarInfo("pkg/a\n::error::pwned.py")
            info.size = len(PLANT)
            tar.addfile(info, io.BytesIO(PLANT))
        result = UnreadableNamesKit.scan(path)
        out = b"".join(Registry().reporter("github").render(result, ReportOptions(color=False)))
        lines = out.decode("utf-8").splitlines()
        assert lines and all(line.startswith("::") for line in lines)  # no line of log text
        assert not any(line.startswith("::error::pwned") for line in lines)  # and no new command
        assert any("a%0A%3A%3Aerror%3A%3Apwned.py" in line for line in lines)  # the name, encoded

    @pytest.mark.parametrize("name", BUILTIN_REPORTERS)
    def test_a_link_whose_name_and_target_are_not_text(self, tmp_path, name) -> None:
        """A tar link member: one kept (it stays inside), one refused (it climbs out), each name
        and target holding a byte that is not UTF-8 and an escape; every report is text."""
        result = UnreadableNamesKit.scan(UnreadableNamesKit.links(tmp_path))
        out = b"".join(Registry().reporter(name).render(result, ReportOptions(color=False)))
        text = out.decode("utf-8")
        for raw in RAW:
            assert raw not in text, f"{name} wrote {raw!r} as it is"

    def test_a_link_name_survives_the_fingerprint_the_cache_and_a_strict_encode(
        self, tmp_path
    ) -> None:
        path = UnreadableNamesKit.links(tmp_path)
        config = Config.default().with_overrides(cache_dir=str(tmp_path / "cache"), use_cache=True)
        for _ in range(2):  # populate, then serve from the cache
            result = Scanner(config).scan(path)
            for finding in result.findings:
                finding.fingerprint.encode("ascii")
            json.dumps(result.to_dict(), ensure_ascii=False).encode("utf-8")  # strict
        assert any(f.rule_id == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" for f in result.findings)

    @pytest.mark.parametrize("make", [UnreadableNamesKit.tarball, UnreadableNamesKit.zipped])
    @pytest.mark.parametrize("name", BUILTIN_REPORTERS)
    def test_every_reporter_writes_the_names_escaped(self, tmp_path, make, name) -> None:
        result = UnreadableNamesKit.scan(make(tmp_path))
        out = b"".join(Registry().reporter(name).render(result, ReportOptions(color=False)))
        text = out.decode("utf-8")  # strict: a report is text a reader can open
        for raw in RAW:
            assert raw not in text, f"{name} wrote {raw!r} as it is"
