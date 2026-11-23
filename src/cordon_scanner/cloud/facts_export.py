"""What a scan may send of what it found, and when: nothing by default, counts only when asked.

The setting `facts_export` is `off` (the default), `counts` or `silver`. With `off` a scan queues nothing about its content. With `counts` it queues one record in the device outbox, the channel the
device's decisions already use, holding the scanner version, the ecosystem, the number of files scanned, the scan's verdict, and the rule ids that fired with how often. It holds no package name,
path, digest, host or code. `silver` is refused until a per-organisation consent exists (`FactsExport.consent` is False until then): a scan with it set sends nothing.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.foundation.results import ScanResult

KIND: Final = "facts-counts"


class FactsExport:
    MODES: ClassVar[tuple[str, ...]] = ("off", "counts", "silver")

    @staticmethod
    def consent() -> bool:
        """Whether an organisation has consented to more than counts. There is no consent record yet, so no."""
        return False

    @classmethod
    def mode_of(cls, value: str) -> str:
        if value not in cls.MODES:
            raise ValueError(f"facts_export is one of {', '.join(cls.MODES)}, not {value!r}")
        return value

    @staticmethod
    def counts(result: ScanResult) -> dict[str, Any]:
        """The counts record of one scan, and nothing else about it."""
        ecosystems = Counter(str(d.ecosystem) for d in result.dependencies if d.ecosystem)
        verdict = result.verdict or {}
        label = str(verdict.get("label") or verdict.get("state") or "none")
        fired = Counter(f.rule_id for f in result.findings if not f.is_suppressed)
        return {
            "scanner": __version__,
            "ecosystem": ecosystems.most_common(1)[0][0] if ecosystems else result.target_kind,
            "files_scanned": result.stats.files_scanned,
            "verdicts": {label: 1},
            "rules": dict(sorted(fired.items())),
        }

    @classmethod
    def queue(cls, mode: str, store: LocalStore, result: ScanResult) -> bool:
        """Queue the counts record when the mode asks for it; whether anything was queued."""
        if cls.mode_of(mode) == "off" or (mode == "silver" and not cls.consent()):
            return False
        body = json.dumps(cls.counts(result), sort_keys=True, separators=(",", ":")).encode()
        return store.enqueue(KIND, body)


__all__ = ["KIND", "FactsExport"]
