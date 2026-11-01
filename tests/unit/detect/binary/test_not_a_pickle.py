"""A file named as a pickle that no pickle loader opens is said to be no pickle, not left
unexamined; one a loader can open, or decompress first, is read as before (item 27)."""

from __future__ import annotations

import collections
import gzip
import io
import pickle
import pickletools
import tarfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.formats.pickles import PickleReader
from cordon_scanner.foundation.config.settings import Config

# the first bytes of the two measured in item 27's count: irispy-lmsal 0.9's IDL save file and
# imitation 1.0's text file named .pkl
IDL_SAVE = b"SR\x00\x04\x00\x00\x00\x0a\x00\x00\x00\x00" + b"\x00" * 64
TEXT = b"version 1\nrollouts 3\n"


class NotAPickleKit:
    @staticmethod
    def sdist(tmp_path, name: str, data: bytes):
        path = tmp_path / "data-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo(f"data-1.0/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)


class TestRefusedAtOnce:
    @pytest.mark.parametrize("raw", [IDL_SAVE, TEXT])
    def test_what_no_loader_opens(self, raw: bytes) -> None:
        assert PickleReader.refused_at_once(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            pickle.dumps({"a": [1, 2]}, protocol=0),
            pickle.dumps({"a": [1, 2]}, protocol=4),
            gzip.compress(pickle.dumps({"a": 1}, protocol=4)),  # a loader decompresses it first
            b"",
        ],
    )
    def test_what_a_loader_may_open(self, raw: bytes) -> None:
        assert not PickleReader.refused_at_once(raw)


# a pickle that imports and calls (GLOBAL and REDUCE), with a harmless object: what makes a file a
# pickle is reaching such an opcode, not what it calls
REDUCES = pickle.dumps(collections.OrderedDict(a=1), protocol=2)


class TestOnceItImportsOrCalls:
    """pickle.load executes as it reads, so a stream that reaches an import or a call is a pickle
    whatever follows: the two ways a "parses to STOP" rule would let one through."""

    def test_bytes_after_stop_do_not_make_it_no_pickle(self) -> None:
        assert REDUCES.endswith(b".")
        assert not PickleReader.refused_at_once(REDUCES + b"x")

    def test_garbage_after_a_call_does_not_make_it_no_pickle(self) -> None:
        # just past the REDUCE, which load has run by then
        cut = next(pos for op, _, pos in pickletools.genops(REDUCES) if op.name == "REDUCE") + 1
        assert not PickleReader.refused_at_once(REDUCES[:cut] + b"\xff\xfe garbage")

    def test_an_import_whose_name_is_cut_still_imports(self) -> None:
        """A GLOBAL with no newline after its name: pickletools refuses the argument, but
        pickle.load imports the module on the first line before it fails."""
        assert not PickleReader.refused_at_once(b"ccollections\nOrderedDict")


class TestPklConfiguration:
    """Apple's Pkl configuration language uses `.pkl` (item 27's count: pkl-typescript 0.0.17)."""

    @pytest.mark.parametrize(
        "text",
        [
            b'amends "pkl:Project"\n\npackage { name = "x" }\n',
            b"module demo.Settings\n\nport: Int = 8080\n",
            b"/// Settings of the demo.\nport = 8080\n",
            b'// a comment\nname = "demo"\n',
        ],
    )
    def test_is_no_pickle(self, text: bytes) -> None:
        assert PickleReader.refused_at_once(text)


class TestAFileThatIsNoPickle:
    def test_is_said_and_the_scan_is_complete(self, tmp_path) -> None:
        result = NotAPickleKit.sdist(tmp_path, "input_calibration.sav", IDL_SAVE)
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.FORMAT.NOT_A_PICKLE" in rules
        assert "OPERATIONAL.FORMAT.UNREADABLE" not in rules
        assert result.content_complete
