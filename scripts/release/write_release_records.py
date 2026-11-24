#!/usr/bin/env python3
"""Write `SHA256SUMS` and one in-toto statement per artefact, for the release page (BP-15-14).

Stdlib only. `verify_artifacts.py` reads exactly what this writes, from one directory holding the release's files. The
statement says which bytes (name and sha256) the release workflow produced, from which repository, commit and run; it is
signed by the build-provenance attestation of the same files, not here.

    python3 scripts/release/write_release_records.py OUT_DIR FILE... [--repo owner/name --commit SHA --run URL]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


class ReleaseRecords:
    """`write(out, files, source)`: the sums file and the statements of `files`, written into `out`."""

    SUMS = "SHA256SUMS"
    STATEMENT = ".intoto.json"
    TYPE = "https://in-toto.io/Statement/v1"
    PREDICATE = "https://cordon.dev/release-artefact/v1"

    @classmethod
    def statement(cls, name: str, digest: str, source: dict[str, str]) -> dict[str, object]:
        return {
            "_type": cls.TYPE,
            "subject": [{"name": name, "digest": {"sha256": digest}}],
            "predicateType": cls.PREDICATE,
            "predicate": source,
        }

    @classmethod
    def write(cls, out: Path, files: list[Path], source: dict[str, str]) -> list[Path]:
        names = [f.name for f in files]
        if len(set(names)) != len(names):
            raise ValueError("two artefacts have one name")
        out.mkdir(parents=True, exist_ok=True)
        written = []
        sums = []
        for path in sorted(files, key=lambda f: f.name):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sums.append(f"{digest}  {path.name}")
            target = out / (path.name + cls.STATEMENT)
            target.write_text(
                json.dumps(cls.statement(path.name, digest, source), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            written.append(target)
        listing = out / cls.SUMS
        listing.write_text("\n".join(sums) + "\n", encoding="utf-8")
        return [listing, *written]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--repo", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--run", default="")
    args = parser.parse_args()
    made = ReleaseRecords.write(
        args.out, args.files, {"repository": args.repo, "commit": args.commit, "run": args.run}
    )
    print(f"wrote {len(made)} files to {args.out}")
    sys.exit(0)
