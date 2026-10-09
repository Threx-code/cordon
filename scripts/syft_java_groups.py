#!/usr/bin/env python3
"""Write `images/data/java-groups.json` from Syft's artifact-to-group map, at a pinned version.

A jar that carries no Maven metadata is named by its file, and its group is guessed. Syft keeps a
curated map from artifact names to the groups that publish them (`ant-antlr` is
`org.apache.ant`), and Cordon consults the same map, after the advisory database's own
coordinates and before any guess, so the two name such a jar alike. Syft is Apache-2.0, as Cordon
is; NOTICE records the source.

    python scripts/syft_java_groups.py                       # fetch the pinned version
    python scripts/syft_java_groups.py --from java_groupid_map.go

Run in a container: the fetch is the only network use, from raw.githubusercontent.com.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

SYFT_VERSION = "v1.18.1"
"""The Syft release the benchmark compares against (`bench/Dockerfile.images`)."""
SOURCE = (
    "https://raw.githubusercontent.com/anchore/syft/{version}/"
    "syft/pkg/cataloger/internal/cpegenerate/java_groupid_map.go"
)
OUT = Path(__file__).resolve().parent.parent / "src/cordon_scanner/images/data/java-groups.json"
ENTRY = re.compile(r'^\s*"([^"]+)":\s*"([^"]+)",\s*$', re.MULTILINE)


class SyftJavaGroups:
    @staticmethod
    def parse(go_source: str) -> dict[str, str]:
        body = go_source.split("DefaultArtifactIDToGroupID", 1)[1]
        return dict(sorted(ENTRY.findall(body)))

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--from", dest="source", type=Path, help="a local copy of the file")
        args = parser.parse_args()
        if args.source:
            text = args.source.read_text(encoding="utf-8")
        else:
            url = SOURCE.format(version=SYFT_VERSION)
            with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https
                text = response.read().decode("utf-8")
        groups = SyftJavaGroups.parse(text)
        if len(groups) < 1000:
            print(
                f"only {len(groups)} entries parsed; the source has changed shape", file=sys.stderr
            )
            return 1
        document = {
            "source": f"anchore/syft {SYFT_VERSION}, cpegenerate.DefaultArtifactIDToGroupID",
            "licence": "Apache-2.0",
            "groups": groups,
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(document, indent=1, sort_keys=False) + "\n", encoding="utf-8")
        print(f"wrote {len(groups)} artifact groups to {OUT.relative_to(OUT.parents[4])}")
        return 0


if __name__ == "__main__":
    sys.exit(SyftJavaGroups.main())
