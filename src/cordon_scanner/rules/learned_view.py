"""What the installed bundle says about its learned detectors, read from the bundle itself and with no network.

An air-gapped install has only what the signed feed last delivered into it: the packs and their index. This lists each learned
detector the index names, with the bundle's date, the detector's age (from the date it was promoted, when the index records one),
how it is enforced and its learned basis (the families it was learned from, how often legitimate packages fire it with the
interval, how many it was measured on, the batch). Nothing is fetched and nothing is sent: a report leaves as a file.
"""

from __future__ import annotations

from datetime import date
from typing import Any, ClassVar

from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.loader import RuleLoader


class LearnedView:
    EXPORT: ClassVar[str] = (
        "This install sends nothing: a report is exported as a file, for example "
        "`cordon-scanner scan . --format json:report.json`."
    )

    @staticmethod
    def when(text: object) -> date | None:
        try:
            return date.fromisoformat(str(text))
        except ValueError:
            return None

    @classmethod
    def lines(cls, today: date) -> list[str]:
        index = FeedRules.index()
        issued = cls.when(index.get("issued"))
        out = [f"learned detectors in the installed bundle (issued {issued or 'date unknown'})"]
        found = 0
        for entry in index.get("packs") or ():
            name = entry.get("file") if isinstance(entry, dict) else None
            path = FeedRules.trusted(name) if isinstance(name, str) else None
            if path is None:
                continue
            promoted = cls.when(entry.get("promoted"))
            age = f"{(today - promoted).days} days" if promoted else "age unknown"
            pack = RuleLoader(require_tests=False).load_text(
                path.read_text(encoding="utf-8"), source=str(path)
            )
            for compiled in pack:
                learned = compiled.rule.raw.get("learned")
                if isinstance(learned, dict):
                    found += 1
                    out.append(
                        f"  {compiled.rule.id}  {entry.get('enforcement', 'block')}  {age}  "
                        + cls.basis(learned)
                    )
        if not found:
            out.append("  none: the bundle carries no learned detector")
        out.append(cls.EXPORT)
        return out

    @staticmethod
    def basis(learned: dict[str, Any]) -> str:
        low, high = learned["interval"]
        parts = [
            f"families={learned['families']}",
            f"legit_rate={learned['legit_rate']:.4f}",
            f"interval={low:.4f}-{high:.4f}",
            f"batch={learned['batch']}",
        ]
        if "n" in learned:
            parts.append(f"n={learned['n']}")
        return " ".join(parts)
