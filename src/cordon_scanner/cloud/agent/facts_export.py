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
    from collections.abc import Mapping, Sequence

    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.foundation.results import ScanResult

KIND: Final = "facts-counts"
AUDIT_KIND: Final = "facts-audit"
HOST_FLOOR: Final = 5
"""A host leaves a machine only when this many organisations report it."""
ANONYMITY_FLOOR: Final = 5
"""A counts record leaves a machine only when this many scans share its ecosystem and verdict."""
FORBIDDEN_KEYS: Final = frozenset(
    {"path", "paths", "path_digest", "config_hash", "rulepack_hash", "pack_hash", "hosts", "names"}
)


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

    @staticmethod
    def silver(
        result: ScanResult, organisations: Mapping[str, int] | None = None
    ) -> dict[str, Any]:
        """The counts record plus the hosts the scan reached that at least `HOST_FLOOR` organisations report.

        `organisations` is the delivered list of hosts with the number of organisations reporting each; a host
        not on it, or on it below the floor, is dropped, and with no list no host is kept."""
        record = FactsExport.counts(result)
        seen = organisations or {}
        reached = {h for hosts, _ in (result.destinations or {}).values() for h in hosts}
        record["hosts"] = sorted(h for h in reached if seen.get(h, 0) >= HOST_FLOOR)
        record["hosts_dropped"] = len(reached) - len(record["hosts"])
        return record

    @staticmethod
    def anonymity_problems(
        records: Sequence[Mapping[str, Any]], floor: int = ANONYMITY_FLOOR
    ) -> list[str]:
        """Why a batch of counts records may not leave the machine: a forbidden key, or a group of scans (same
        ecosystem and verdict) smaller than `floor`."""
        problems = [
            f"a record carries {key!r}"
            for key in sorted({k for r in records for k in r} & FORBIDDEN_KEYS)
        ]
        groups = Counter(
            (r.get("ecosystem"), tuple(sorted(r.get("verdicts", {})))) for r in records
        )
        problems += [
            f"{n} scans share {g[0]}/{'+'.join(g[1])}, fewer than {floor}"
            for g, n in sorted(groups.items(), key=str)
            if n < floor
        ]
        return problems

    @classmethod
    def release(cls, store: LocalStore, floor: int = ANONYMITY_FLOOR) -> list[dict[str, Any]]:
        """The queued counts records, or `ValueError` when a group is below the floor or a record is not counts only."""
        records = [json.loads(item.body) for item in store.pending() if item.kind == KIND]
        problems = cls.anonymity_problems(records, floor)
        if problems:
            raise ValueError("the facts cannot leave this machine: " + "; ".join(problems))
        return records

    @classmethod
    def queue(
        cls,
        mode: str,
        store: LocalStore,
        result: ScanResult,
        *,
        consent: bool | None = None,
        organisations: Mapping[str, int] | None = None,
    ) -> bool:
        """Queue the record the mode asks for; whether anything was queued. `silver` needs consent and then
        carries the hosts at or above the floor, with one audit record of how many hosts were kept and dropped."""
        if cls.mode_of(mode) == "off":
            return False
        if mode == "silver" and not (cls.consent() if consent is None else consent):
            return False
        record = cls.silver(result, organisations) if mode == "silver" else cls.counts(result)
        queued = store.enqueue(
            KIND, json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        )
        if queued and mode == "silver":
            audit = {
                "hosts_sent": len(record["hosts"]),
                "hosts_dropped": record["hosts_dropped"],
                "floor": HOST_FLOOR,
            }
            store.enqueue(
                AUDIT_KIND, json.dumps(audit, sort_keys=True, separators=(",", ":")).encode()
            )
        return queued


__all__ = ["ANONYMITY_FLOOR", "AUDIT_KIND", "HOST_FLOOR", "KIND", "FactsExport"]
