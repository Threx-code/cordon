"""A name made text where it enters (`foundation/files/names.py`, item 34): always valid UTF-8, the
same for every name that is text already, and never two names made one."""

from __future__ import annotations

import sys
from pathlib import PurePosixPath

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.files.names import Names
from cordon_scanner.sources.archive import ArchiveReader

DECODE = "b64" + "decode"
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
).encode()

# a name as an archive or `os.scandir` hands it on: any bytes, decoded with surrogateescape
NAMES = st.binary(min_size=1, max_size=24).map(lambda raw: raw.decode("utf-8", "surrogateescape"))


class TestNamesAsText:
    @settings(max_examples=2_000, deadline=None)
    @given(NAMES)
    def test_every_name_becomes_valid_text(self, name: str) -> None:
        Names.text(name, backslash=True).encode("utf-8")
        Names.text(name).encode("utf-8")

    @settings(max_examples=2_000, deadline=None)
    @given(NAMES, NAMES)
    def test_two_walked_names_are_never_made_one(self, a: str, b: str) -> None:
        if a != b:
            assert Names.text(a, backslash=True) != Names.text(b, backslash=True)

    @settings(max_examples=2_000, deadline=None)
    @given(NAMES, NAMES)
    def test_two_member_names_are_never_made_one(self, a: str, b: str) -> None:
        """A member's name is normalised first, so it never holds a backslash: on names without one,
        the escape alone keeps two names apart."""
        a, b = a.replace("\\", ""), b.replace("\\", "")
        if a != b:
            assert Names.text(a) != Names.text(b)

    @pytest.mark.parametrize("name", ["README.md", "pkg/a b.py", "é/ü.js", "\u202eyp.txt.py"])
    def test_a_name_that_is_text_is_untouched(self, name: str) -> None:
        assert Names.text(name) == name
        assert Names.text(name, backslash=True) == name

    def test_a_byte_is_shown_and_a_walked_backslash_kept_apart(self) -> None:
        assert Names.text("run\udca7.py") == "run\\xa7.py"
        assert Names.text("run\\xa7.py", backslash=True) == "run\\x5cxa7.py"

    def test_a_member_is_made_text_after_it_is_normalised(self) -> None:
        """The escape's backslash is never read as a separator, and `..` is still refused."""
        safe = ArchiveReader.safe_member_name("pkg/a\udcff.js")
        assert safe == "pkg/a\\xff.js" and PurePosixPath(safe).parts == ("pkg", "a\\xff.js")
        assert ArchiveReader.safe_member_name("pkg/../../\udcff.js") is None


class TestALinkIsMeasuredOnTheNormalisedName:
    def test_an_escaped_byte_never_deepens_a_link(self) -> None:
        """Measured on the escaped name, `a/b\\xff/l`'s backslash would be a separator: three
        directories, and `../../../x` judged inside. On the normalised name it climbs out."""
        name, target = "a/b\udcff/l", "../../../x"
        normal = ArchiveReader.normalise_member_name(name)
        assert normal is not None
        assert not ArchiveReader.link_stays_inside(normal, target)
        assert ArchiveReader.link_stays_inside(Names.text(normal), target)  # why the order matters


@pytest.mark.skipif(
    sys.platform != "linux", reason="a filename that is not UTF-8: Linux file systems only"
)
class TestAWalkedNameThatIsNotText:
    def test_the_file_is_scanned_and_graded(self, tmp_path) -> None:
        raw = bytes(tmp_path) + b"/run\xa7.py"
        with open(raw, "wb") as handle:  # noqa: PTH123 -- a bytes path, which no Path holds
            handle.write(PLANT)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert {
            f.location.path for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"
        } == {"run\\xa7.py"}
