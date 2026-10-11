"""A scanner run, turned into what an agent acts on.

The verdict is the scanner's own: `block` when its failure policy fails the scan (exit 1 -- the same
gate CI applies, including an organisation policy), `warn` when it passes but reports something at
medium or above, `pass` when nothing at medium or above was found, and `incomplete` when the scanner
says it could not read everything. An incomplete scan is never called a pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Final

from cordon_scanner.mcp.untrusted import NOTICE, Untrusted

SEVERITIES: Final[tuple[str, ...]] = ("critical", "high", "medium", "low", "info")
_RANK: Final = {s: i for i, s in enumerate(SEVERITIES)}

#: The structured result every scanning tool returns.
SCAN_OUTPUT: Final[dict[str, Any]] = {
    "type": "object",
    "required": ["verdict", "summary", "counts", "total_findings", "findings", "complete", "notes"],
    "properties": {
        "verdict": {"enum": ["block", "warn", "pass", "incomplete"]},
        "summary": {"type": "string"},
        "counts": {
            "type": "object",
            "properties": {s: {"type": "integer"} for s in SEVERITIES},
        },
        "total_findings": {"type": "integer"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["rule_id", "severity", "message"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "severity": {"type": "string"},
                    "confidence": {"type": "string"},
                    "category": {"type": "string"},
                    "title": {"type": "string"},
                    "message": {"type": "string"},
                    "remediation": {"type": "string"},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "package": {"type": "string"},
                    "detail": {"type": "string"},
                    "fingerprint": {"type": "string"},
                },
            },
        },
        "truncated": {"type": "boolean"},
        "complete": {"type": "boolean"},
        "notes": {"type": "array", "items": {"type": "string"}},
        "subject": {"type": "object"},
        "scanner": {"type": "object"},
    },
}


@dataclass(slots=True)
class ScanSummary:
    verdict: str
    summary: str
    counts: dict[str, int]
    findings: list[dict[str, Any]]
    total: int
    complete: bool
    notes: list[str] = field(default_factory=list)
    subject: dict[str, Any] = field(default_factory=dict)
    scanner: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False

    def structured(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "summary": self.summary,
            "counts": self.counts,
            "total_findings": self.total,
            "findings": self.findings,
            "truncated": self.truncated,
            "complete": self.complete,
            "notes": self.notes,
            "subject": self.subject,
            "scanner": self.scanner,
        }

    def text(self) -> str:
        lines = [f"{self.verdict.upper()}: {self.summary}"]
        for finding in self.findings[:15]:
            where = finding.get("package") or finding.get("path") or ""
            line = f":{finding['line']}" if finding.get("line") else ""
            lines.append(
                f"- [{finding['severity']}] {finding['rule_id']} {where}{line}: {finding.get('title') or finding['message'][:200]}"
            )
        if self.total > 15:
            lines.append(f"- ... {self.total - 15} more in the structured result")
        lines.extend(f"note: {n}" for n in self.notes)
        lines.append(NOTICE)
        return "\n".join(lines) + "\n\n" + json.dumps(self.structured(), ensure_ascii=False)


class Results:
    @staticmethod
    def finding(raw: dict[str, Any]) -> dict[str, Any]:
        location = raw.get("location") or {}
        evidence = raw.get("evidence") or {}
        metadata = evidence.get("metadata") or {}
        explanation = raw.get("explanation") or {}
        out: dict[str, Any] = {
            "rule_id": Untrusted.text(raw.get("rule_id", ""), 200),
            "severity": str(raw.get("severity", "")),
            "confidence": str(raw.get("confidence", "")),
            "category": str(raw.get("category", "")),
            "title": Untrusted.text(explanation.get("summary", ""), 300),
            "message": Untrusted.text(raw.get("message", ""), 1500),
            "remediation": Untrusted.text(raw.get("remediation", ""), 800),
            "path": Untrusted.text(location.get("path", ""), 500),
            "fingerprint": str(raw.get("fingerprint", "")),
        }
        if isinstance(location.get("line"), int):
            out["line"] = location["line"]
        if location.get("package"):
            out["package"] = Untrusted.text(location["package"], 300)
        if metadata.get("detail"):
            out["detail"] = Untrusted.text(metadata["detail"], 500)
        return {k: v for k, v in out.items() if v not in ("", None)}

    @classmethod
    def summarise(
        cls,
        document: dict[str, Any],
        exit_code: int,
        *,
        max_findings: int,
        subject: dict[str, Any] | None = None,
        notes: list[str] | None = None,
        root_prefix: str = "",
        package_only: bool = False,
    ) -> ScanSummary:
        raw = [f for f in document.get("findings") or [] if isinstance(f, dict)]
        if package_only:
            # A package check scans a lockfile written for it: a finding about that file (no
            # hashes, how it pins) is about the stand-in, not the package, and is left out.
            raw = [
                f
                for f in raw
                if (f.get("location") or {}).get("package") or f.get("category") == "operational"
            ]
            if exit_code == 1 and not any(f.get("category") != "operational" for f in raw):
                exit_code = 0  # the gate failed only on findings about the stand-in file
        operational = [f for f in raw if f.get("category") == "operational"]
        threats = [f for f in raw if f.get("category") != "operational"]
        threats.sort(
            key=lambda f: (
                _RANK.get(str(f.get("severity")), 9),
                str(f.get("rule_id")),
                str((f.get("location") or {}).get("path")),
            )
        )
        counts = dict.fromkeys(SEVERITIES, 0)
        for f in threats:
            sev = str(f.get("severity"))
            if sev in counts:
                counts[sev] += 1
        findings = [cls.finding(f) for f in threats[:max_findings]]
        if root_prefix:
            for f in findings:
                if f.get("path", "").startswith(root_prefix):
                    f["path"] = f["path"][len(root_prefix) :]
        complete = bool(document.get("complete", True)) and exit_code != 4
        all_notes = list(notes or [])
        for f in operational[:20]:
            all_notes.append(Untrusted.text(f"{f.get('rule_id')}: {f.get('message', '')}", 600))
        serious = counts["critical"] + counts["high"] + counts["medium"]
        if exit_code == 1:
            verdict = "block"
        elif not complete:
            verdict = "incomplete"
        elif serious:
            verdict = "warn"
        else:
            verdict = "pass"
        worst = next((s for s in SEVERITIES if counts[s]), None)
        if not threats:
            summary = "no findings" + (
                "" if complete else ", but the scan could not read everything (see notes)"
            )
        else:
            summary = f"{len(threats)} finding(s), highest {worst}"
            if verdict == "block":
                summary += "; the scanner's failure policy fails this"
        intel = document.get("intel") or {}
        scanner = {
            "engine_version": document.get("engine_version"),
            "rulepack_version": document.get("rulepack_version"),
            "intel_source": intel.get("source"),
            "intel_age_days": round(int(intel.get("age_seconds") or 0) / 86400, 1),
            "intel_stale": intel.get("stale"),
        }
        return ScanSummary(
            verdict=verdict,
            summary=summary,
            counts=counts,
            findings=findings,
            total=len(threats),
            complete=complete,
            notes=all_notes,
            subject=Untrusted.tree(subject or {}, 500),
            scanner=scanner,
            truncated=len(threats) > max_findings,
        )

    @staticmethod
    def merge(
        parts: list[ScanSummary], *, max_findings: int, subject: dict[str, Any]
    ) -> ScanSummary:
        """Several scans of one request (a command's packages, a server and what it launches)."""
        order = ["block", "incomplete", "warn", "pass"]
        verdict = min((p.verdict for p in parts), key=order.index) if parts else "pass"
        counts = dict.fromkeys(SEVERITIES, 0)
        findings: list[dict[str, Any]] = []
        notes: list[str] = []
        for p in parts:
            for s in SEVERITIES:
                counts[s] += p.counts.get(s, 0)
            findings.extend(p.findings)
            notes.extend(p.notes)
        findings.sort(key=lambda f: (_RANK.get(f.get("severity", ""), 9), f.get("rule_id", "")))
        total = sum(p.total for p in parts)
        worst = next((s for s in SEVERITIES if counts[s]), None)
        summary = "no findings" if not total else f"{total} finding(s), highest {worst}"
        if verdict == "block":
            summary += "; the scanner's failure policy fails this"
        if verdict == "incomplete":
            summary += "; part of it could not be checked (see notes)"
        return ScanSummary(
            verdict=verdict,
            summary=summary,
            counts=counts,
            findings=findings[:max_findings],
            total=total,
            complete=all(p.complete for p in parts),
            notes=list(dict.fromkeys(notes)),
            subject=Untrusted.tree(subject, 500),
            scanner=parts[0].scanner if parts else {},
            truncated=total > max_findings or any(p.truncated for p in parts),
        )
