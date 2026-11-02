"""Release step: the look-up table beside every shipped advisory file (item 74).

`intel/advisories/shipped_table.py` reads a table that names its data file's own digest, so a table
built from a different file is never used; run this after the data files change.

    python -P scripts/build/build_advisory_tables.py [data_dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

from cordon_scanner.intel.advisories.advisories import DATA_DIR
from cordon_scanner.intel.advisories.shipped_table import ShippedTable


class BuildAdvisoryTables:
    """The release step's entry point."""

    @staticmethod
    def main() -> int:
        data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_DIR
        for table in ShippedTable.write_for(data_dir):
            print(f"{table.name} {table.stat().st_size}")
        return 0


if __name__ == "__main__":
    raise SystemExit(BuildAdvisoryTables.main())
