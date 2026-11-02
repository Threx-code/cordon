"""Release step: the bundled rule patterns' derivations, beside the packs (item 74, cut 3).

`rules/derivations.py` reads a table that names the derivation code's digest and the Python it was
built under, so a table from other code or another Python is never used; run this after a pack or
`rules/patterns.py` changes.

    python -P scripts/build/build_rule_derivations.py
"""

from __future__ import annotations

import json

from cordon_scanner.rules.derivations import TABLE, PatternDerivations
from cordon_scanner.rules.loader import RuleLoader


class BuildRuleDerivations:
    """The release step's entry point."""

    @staticmethod
    def main() -> int:
        target = PatternDerivations.directory() / TABLE
        document = PatternDerivations.document(*RuleLoader.bundled_patterns())
        target.write_text(json.dumps(document, indent=0, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{target.name} {target.stat().st_size}")
        return 0


if __name__ == "__main__":
    raise SystemExit(BuildRuleDerivations.main())
