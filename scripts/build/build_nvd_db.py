#!/usr/bin/env python3
"""Refresh the shipped NVD-derived data: `nvd-cves.json.gz` and `nvd-cpe.json.gz` (see `intel/nvd`).

A MAINTENANCE script, the same arrangement as `build_advisory_db.py`: never imported by the scanner,
never run during a scan or a package build. Its output is a reviewed artefact that ships with the
release.

    python3 scripts/build/build_nvd_db.py            # high, critical, unrated and exploited (bundled)
    python3 scripts/build/build_nvd_db.py --full     # every severity
    python3 scripts/build/build_nvd_db.py --check    # fetch and verify, write nothing

For a CVE NVD has not analysed -- no CPE configuration, so no range -- the ranges its own record in
the CVE List states are added (`intel/cve_list`): its CPEs and affected versions, from its CNA or
an ADP such as CISA's Vulnrichment. `--no-cve-list` builds from NVD alone.

What ships is filtered the way the OSV data is, and for the same reason (`build_advisory_db.py`'s
docstring): a record the default policy would not fail a build on stays one
`cordon-scanner advisories sync` away. A CVE in CISA's KEV or ENISA's EUVD catalogue is always
kept, whatever its rating. All or nothing: a feed that fails to download or to match its published
SHA-256 writes nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = next((p for p in (Path.cwd(), *Path.cwd().parents) if (p / "src" / "cordon_scanner").is_dir()), None) or sys.exit(
    "run this from inside the Cordon repository"
)
sys.path.insert(0, str(ROOT / "src"))

from cordon_scanner.intel.advisories import exploited, nvd, nvd_import  # noqa: E402

_HIGH_VALUE = frozenset({"high", "critical", ""})


class NvdDatabaseBuild:
    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--full", action="store_true", help="bundle every severity")
        parser.add_argument("--check", action="store_true", help="fetch and verify; write nothing")
        parser.add_argument(
            "--no-cve-list",
            action="store_true",
            help="NVD alone, without the CVE List's ranges for CVEs NVD has not analysed",
        )
        parser.add_argument(
            "--output",
            default=str(ROOT / "src" / "cordon_scanner" / "intel" / "data"),
            metavar="DIR",
        )
        args = parser.parse_args()
        output = Path(args.output)
        exploited_cves: frozenset[str] = frozenset()
        try:
            document = json.loads((output / exploited.EXPLOITED_NAME).read_text(encoding="utf-8"))
            exploited_cves = frozenset(str(c).upper() for c in (document.get("entries") or {}))
        except (OSError, ValueError, AttributeError):
            print("  no exploited catalogue beside the data: keeping by rating alone")

        def keep(identifier: str, rating: str) -> bool:
            return args.full or rating in _HIGH_VALUE or identifier.upper() in exploited_cves

        print("NVD:")
        try:
            built = nvd_import.NvdImport.build(
                nvd_import.NvdImport.years(),
                keep,
                cve_list=() if args.no_cve_list else nvd_import.NvdImport.cve_list_records(),
            )
        except nvd_import.NvdImportError as exc:
            print(f"  FAILED: {exc}", file=sys.stderr)
            print("nothing was written; re-run once every feed answers.", file=sys.stderr)
            return 1
        pairs = sum(len(v) for v in built.products.values())
        print(
            f"  {built.cves:,} CVEs read; kept {len(built.text):,} with application ranges, "
            f"{pairs:,} product ranges across {len(built.products):,} products"
        )
        if args.check:
            return 0
        nvd_import.NvdImport.write(output, built, filtered=not args.full, seal=False)
        print(f"wrote {nvd.CVES_NAME} and {nvd.CPE_NAME} to {output}")
        return 0


if __name__ == "__main__":
    raise SystemExit(NvdDatabaseBuild.main())
