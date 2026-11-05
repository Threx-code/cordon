#!/usr/bin/env python3
"""Build `intel/data/campaign-fingerprints.json.gz`: condemned npm releases by their campaign
fingerprints, for `detect/supply/campaign_sibling.py` (review 98 C3).

    python scripts/build/build_campaign_fingerprints.py CONDEMNED.jsonl BENIGN.txt OUT [GENERATED]

CONDEMNED.jsonl has one condemned release per line: `path` (its npm tarball), `name`, `version`, `id`
(the advisory, an OSV MAL- id) and `published` (when the advisory was). BENIGN.txt lists the reference
tarballs of ordinary packages, one path per line -- random and popular npm releases. Each tarball is
read for its top-level `package.json` and its member names only; nothing in it is run or decoded.

`CampaignIndex.build` does the rest: facet values common among the reference packages link nothing,
and a condemned fingerprint corroborating any reference package is left out, so a clone never puts
the signal on the original it copied. The output is deterministic for the same inputs (sorted
records, gzip without a timestamp), so a rebuild that changes nothing changes no bytes.

Build it only from condemned releases a study may read: never from a held-out test set, so a
measurement scored with the shipped index cannot be scored on what built it.
"""

from __future__ import annotations

import gzip
import json
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cordon_scanner.intel.malware.campaign import CampaignFingerprint, CampaignIndex

MAX_MANIFEST = 1 << 20


class CampaignBuild:
    @staticmethod
    def facets(path: str) -> dict[str, str | None] | None:
        """One tarball's facets, or None when it cannot be read."""
        try:
            with tarfile.open(path) as archive:
                members = [m for m in archive.getmembers() if m.isreg()]
                top = next(
                    (
                        m
                        for m in members
                        if m.name.count("/") == 1
                        and m.name.endswith("/package.json")
                        and m.size < MAX_MANIFEST
                    ),
                    None,
                )
                handle = archive.extractfile(top) if top is not None else None
                manifest = json.loads(handle.read()) if handle is not None else {}
        except (OSError, ValueError, tarfile.TarError, EOFError):
            return None
        return CampaignFingerprint.of(
            manifest if isinstance(manifest, dict) else {}, [m.name for m in members]
        )

    @classmethod
    def main(cls, argv: list[str]) -> int:
        if len(argv) not in (3, 4):
            print(__doc__, file=sys.stderr)
            return 2
        condemned_list, benign_list, out = argv[:3]
        generated = argv[3] if len(argv) == 4 else datetime.now(UTC).strftime("%Y-%m-%d")
        condemned: list[tuple[dict[str, str | None], dict[str, Any]]] = []
        for line in Path(condemned_list).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            facets = cls.facets(row["path"])
            if facets is not None:
                record = {k: str(row.get(k, "")) for k in ("name", "version", "id", "published")}
                condemned.append((facets, record))
        benign = [
            f
            for p in Path(benign_list).read_text(encoding="utf-8").split()
            if (f := cls.facets(p)) is not None
        ]
        document = CampaignIndex.build(condemned, benign, generated)
        text = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        Path(out).write_bytes(gzip.compress(text, mtime=0))
        print(
            f"{len(document['records'])} of {len(condemned)} condemned fingerprints shipped; "
            f"{len(benign)} reference packages"
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(CampaignBuild.main(sys.argv[1:]))
