"""Packs the MCP coverage fixture tree into one deterministic archive, `bench/mcp_coverage/fixtures.tar.gz`.

    PYTHONPATH=src:tests:. python -m bench.mcp_coverage.pack

The kit (`build.py`, `code_families.py`, `text_families.py`) writes `corpus/coverage/mcp/`; that tree is several thousand
attack-shaped fixtures, so the repository keeps it as one archive and the tests unpack it into a temporary folder
(`tests/support.py`, `CoverageTree`). The archive is byte-identical for the same tree: members sorted, owner and group 0,
times 0, modes 0644 and 0755, gzip time 0. `coverage-baseline.json` stays beside it as `coverage-baseline.json`, because
`test_mcp_coverage.py --update` rewrites it.
"""

from __future__ import annotations

import gzip
import io
import shutil
import sys
import tarfile
from pathlib import Path

from support import ROOT


class CoveragePack:
    TREE = ROOT / "corpus" / "coverage" / "mcp"
    ARCHIVE = ROOT / "bench" / "mcp_coverage" / "fixtures.tar.gz"
    BASELINE = ROOT / "bench" / "mcp_coverage" / "coverage-baseline.json"

    @staticmethod
    def members(tree: Path) -> list[Path]:
        return sorted(p for p in tree.rglob("*") if p.name != "coverage-baseline.json")

    @classmethod
    def pack(cls) -> int:
        if not cls.TREE.is_dir():
            print(f"no tree at {cls.TREE}: run the kit first", file=sys.stderr)
            return 2
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for path in cls.members(cls.TREE):
                info = tar.gettarinfo(
                    str(path), arcname=f"mcp/{path.relative_to(cls.TREE).as_posix()}"
                )
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.mode = 0o755 if path.is_dir() else 0o644
                if path.is_file():
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)
                else:
                    tar.addfile(info)
        with (
            cls.ARCHIVE.open("wb") as out,
            gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz,
        ):
            gz.write(raw.getvalue())
        baseline = cls.TREE / "coverage-baseline.json"
        if baseline.is_file():
            shutil.copyfile(baseline, cls.BASELINE)
        print(f"{cls.ARCHIVE.relative_to(ROOT)}: {len(cls.members(cls.TREE))} members")
        return 0


if __name__ == "__main__":
    raise SystemExit(CoveragePack.pack())
