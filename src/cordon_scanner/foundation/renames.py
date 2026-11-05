"""Names that changed: rule IDs and detector IDs a release renamed, kept so nothing built on the
old ones breaks.

An old rule ID in a suppression still suppresses the finding it named, and a renamed rule's
findings keep the fingerprint they always had -- computed from the ID the rule was first
published under -- so a baseline, a suppression by fingerprint and a code-scanning platform's
alerts all carry across the rename. An old detector ID in a configuration still names the
detector. Old names are accepted for one release and then dropped.
"""

from __future__ import annotations

import os
import sys
from typing import Any, ClassVar


class Renamed:
    """Old name -> current name, for rules and for detectors."""

    RULES: ClassVar[dict[str, str]] = {
        "SUSPECT.YARA.MATCH.001": "SUSPECT.RULEFILE.MATCH.001",
        "MALWARE.YARA.MATCH.001": "MALWARE.RULEFILE.MATCH.001",
        "OPERATIONAL.YARA.STATUS": "OPERATIONAL.RULEFILE.STATUS",
        "OPERATIONAL.YARA.UNAVAILABLE": "OPERATIONAL.RULEFILE.UNAVAILABLE",
    }
    DETECTORS: ClassVar[dict[str, str]] = {"yara": "rule-file"}
    #: Current rule ID -> the ID its fingerprint is computed from.
    FIRST: ClassVar[dict[str, str]] = {new: old for old, new in RULES.items()}

    @staticmethod
    def rule(rule_id: str) -> str:
        """The current ID for `rule_id` (itself, if it was never renamed)."""
        return Renamed.RULES.get(rule_id, rule_id)

    @staticmethod
    def first(rule_id: str) -> str:
        """The ID a rule was first published under: what its findings are fingerprinted with."""
        return Renamed.FIRST.get(rule_id, rule_id)

    @staticmethod
    def detector(detector_id: str) -> str:
        return Renamed.DETECTORS.get(detector_id, detector_id)

    @staticmethod
    def rule_file(args: Any, program: str) -> str | None:
        """The rule file a scan was given: `--rule-file` / CORDON_RULE_FILE, or -- with a warning --
        the option and variable it was named by before 0.7.0 (`--yara`, CORDON_YARA)."""
        current = getattr(args, "rule_file", None)
        old = getattr(args, "rule_file_old", None) or os.environ.get("CORDON_YARA")
        if old and not current:
            print(
                f"{program}: --yara and CORDON_YARA are deprecated and will be removed in the "
                "next release: use --rule-file or CORDON_RULE_FILE",
                file=sys.stderr,
            )
            return str(old)
        return current


__all__ = ["Renamed"]
