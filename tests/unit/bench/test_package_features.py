"""The package-wide code features of an archive (`bench/tools/package_features.py`): the same extractor as
the scanner's `package` place, run over the archive's Python members with no scan. Archives are built
here in a temporary directory; no corpus is read."""

from __future__ import annotations

import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "tools"))

from package_features import PackageFeatures

from cordon_scanner.detect.code.features import CodeFeatures

# Distinctive literals: none of them may appear in any feature key.
MARKER = "zqxmarkerhost"
A = f"import os\nv = os.environ.get('{MARKER}key')\nrun(['curl', 'https://{MARKER}.example'])\n"
B = "import subprocess\nsubprocess.run(['ls'])\n"


class Archives:
    @staticmethod
    def tar(path: Path, members: dict[str, bytes]) -> Path:
        with tarfile.open(path, "w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def zip(path: Path, members: dict[str, bytes]) -> Path:
        with zipfile.ZipFile(path, "w") as bundle:
            for name, data in members.items():
                bundle.writestr(name, data)
        return path

    MEMBERS: dict[str, bytes] = {  # noqa: RUF012
        "pkg-1.0/pkg/__init__.py": A.encode(),
        "pkg-1.0/pkg/other.py": B.encode(),
        "pkg-1.0/README.md": b"not python",
        "pkg-1.0/pkg/data.json": b"{}",
    }


class TestTheRow:
    def expected(self) -> dict[str, float]:
        return CodeFeatures.of({"package": [("a.py", A.encode()), ("b.py", B.encode())]})

    @pytest.mark.parametrize("make", [Archives.tar, Archives.zip], ids=["tar", "zip"])
    def test_the_features_are_those_of_the_python_members_read_whole(
        self, tmp_path: Path, make
    ) -> None:
        name = "x-1.0.tar.gz" if make is Archives.tar else "x-1.0-py3-none-any.whl"
        make(tmp_path / name, Archives.MEMBERS)
        row = PackageFeatures.row(tmp_path, name)
        assert row["features"] == self.expected()
        assert (row["py_files"], row["truncated"]) == (2, False)
        assert row["py_bytes"] == len(A) + len(B)

    def test_the_same_archive_gives_the_same_row(self, tmp_path: Path) -> None:
        Archives.tar(tmp_path / "x.tar.gz", Archives.MEMBERS)
        assert PackageFeatures.row(tmp_path, "x.tar.gz") == PackageFeatures.row(
            tmp_path, "x.tar.gz"
        )

    def test_only_the_package_place_is_made_and_no_string_value_is_in_a_key(
        self, tmp_path: Path
    ) -> None:
        Archives.tar(tmp_path / "x.tar.gz", Archives.MEMBERS)
        keys = list(PackageFeatures.row(tmp_path, "x.tar.gz")["features"])
        assert keys
        assert all(k.startswith("code_package_") for k in keys)
        assert not any(MARKER in k for k in keys)

    def test_a_file_read_in_windows_gives_what_it_gives_whole(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        big = (A * 40).encode()
        Archives.tar(tmp_path / "x.tar.gz", {"p/big.py": big})
        whole = PackageFeatures.row(tmp_path, "x.tar.gz")["features"]
        monkeypatch.setattr(CodeFeatures, "WINDOW", 97)
        assert PackageFeatures.row(tmp_path, "x.tar.gz")["features"] == whole

    def test_a_member_past_the_limit_is_left_unread_and_said(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Archives.tar(tmp_path / "x.tar.gz", Archives.MEMBERS)
        monkeypatch.setattr(PackageFeatures, "MAX_MEMBER", len(B))
        row = PackageFeatures.row(tmp_path, "x.tar.gz")
        assert (row["py_files"], row["truncated"]) == (1, True)

    def test_an_archive_that_is_not_one_is_an_error_row_not_a_stop(self, tmp_path: Path) -> None:
        (tmp_path / "x.tar.gz").write_bytes(b"not an archive at all")
        (tmp_path / "y.whl").write_bytes(b"not an archive either")
        assert PackageFeatures.row(tmp_path, "x.tar.gz")["error"]
        assert PackageFeatures.row(tmp_path, "y.whl")["error"]
        assert PackageFeatures.row(tmp_path, "missing.tar.gz")["error"]

    def test_an_archive_with_no_python_has_no_features(self, tmp_path: Path) -> None:
        Archives.tar(tmp_path / "x.tar.gz", {"p/README": b"hi"})
        row = PackageFeatures.row(tmp_path, "x.tar.gz")
        assert row["features"] == {}
        assert row["py_files"] == 0


class TestTheRun:
    def test_a_run_writes_one_row_a_unit_and_resumes(self, tmp_path: Path) -> None:
        Archives.tar(tmp_path / "a.tar.gz", Archives.MEMBERS)
        Archives.zip(tmp_path / "b.whl", Archives.MEMBERS)
        (tmp_path / "c.tar.gz").write_bytes(b"broken")
        listing = tmp_path / "units.txt"
        listing.write_text("a.tar.gz\nb.whl\nc.tar.gz\n", encoding="utf-8")
        out = tmp_path / "out" / "rows.jsonl"
        out.parent.mkdir()
        first = PackageFeatures.run(listing, tmp_path, out, workers=2)
        assert (first["listed"], first["read"], first["errors"], first["resumed"]) == (3, 2, 1, 0)
        rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        assert sorted(r["file"] for r in rows) == ["a.tar.gz", "b.whl", "c.tar.gz"]
        again = PackageFeatures.run(listing, tmp_path, out, workers=2)
        assert (again["read"], again["errors"], again["resumed"]) == (0, 0, 3)
        assert len(out.read_text(encoding="utf-8").splitlines()) == 3
