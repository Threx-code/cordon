"""JSON output. The canonical form.

Every other format is a transformation of this one. That is a deliberate
constraint rather than an accident of implementation: it guarantees the formats
cannot drift apart, and it makes ``cordon report convert`` possible, so a result
saved today can be rendered as SARIF next year without re-scanning code that may
no longer exist in that form.

The output is schema-versioned and deterministic. Keys are sorted, findings are
ordered by the domain's own total ordering, and nothing includes a timestamp.
Two scans of identical content produce byte-identical JSON, which is what makes
result diffing meaningful and caching sound.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cordon_scanner.report.base import BaseReporter, Escape, ReportOptions
from cordon_scanner.report.claims import Claims

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.foundation.results import ScanResult


class JsonReporter(BaseReporter):
    id = "json"
    media_type = "application/json"
    file_extension = ".json"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        payload = result.to_dict()
        # What each finding claims (malware, risky behaviour, policy), and what the blocked unit
        # claims from the findings that block it. Report-only: the gate decided before this ran
        # (`report/claims.py`).
        for finding, row in zip(result.findings, payload["findings"], strict=True):
            claim = Claims.of_finding(finding)
            if claim is not None:
                row["claim"] = str(claim)
        if opts.blocking:
            unit = Claims.of_unit(f for f in result.findings if f.fingerprint in opts.blocking)
            if unit is not None:
                payload["claim"] = str(unit)

        if not opts.show_suppressed:
            payload["findings"] = [f for f in payload["findings"] if "suppressed" not in f]

        if opts.max_findings and len(payload["findings"]) > opts.max_findings:
            payload["findings"] = payload["findings"][: opts.max_findings]
            # A truncated report that does not say so is a report that lies.
            payload["truncated"] = True

        # every character no reader should meet raw (a bidi override or lone surrogate in a name)
        # as its JSON escape: the same document to a program (`Escape.json`)
        yield Escape.json(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        ).encode("utf-8")
        yield b"\n"


__all__ = ["JsonReporter"]
