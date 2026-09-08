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

from cordon.report.base import BaseReporter, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon.core.models import ScanResult


class JsonReporter(BaseReporter):
    id = "json"
    media_type = "application/json"
    file_extension = ".json"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        payload = result.to_dict()

        if not opts.show_suppressed:
            payload["findings"] = [
                f for f in payload["findings"] if "suppressed" not in f
            ]

        if opts.max_findings and len(payload["findings"]) > opts.max_findings:
            payload["findings"] = payload["findings"][: opts.max_findings]
            # A truncated report that does not say so is a report that lies.
            payload["truncated"] = True

        yield json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        yield b"\n"


__all__ = ["JsonReporter"]
