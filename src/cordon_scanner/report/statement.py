"""`--format statement`: the scan as an in-toto statement whose predicate is the `scan/v1` record.

The predicate is the scan's minimal record (`cloud/minimal_record.py`: findings by rule, severity, confidence, category, detector, fingerprint, location and the hash of what matched; whether the scan completed
and the rule ids of what it could not read; the versions). The statement binds it to its own bytes: the one subject is the record, named and digested, so a signature over the statement covers the predicate
byte for byte. The statement is checked against the statement schema and the `scan/v1` schema before it is written, and nothing is written for one that does not pass.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.cloud.minimal_record import MinimalRecord
from cordon_scanner.contracts.schemas import PREDICATE_PREFIX, Statements
from cordon_scanner.foundation.errors import CordonError
from cordon_scanner.report.base import BaseReporter, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.foundation.results import ScanResult

STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE: Final = PREDICATE_PREFIX + "scan/v1"
SUBJECT_NAME: Final = "cordon-scan.json"


class ScanStatement:
    @staticmethod
    def canonical(document: dict[str, Any]) -> bytes:
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    @classmethod
    def of(cls, result: ScanResult) -> dict[str, Any]:
        """The statement for `result`, valid by construction or `CordonError`."""
        predicate = MinimalRecord.of(result)
        statement = {
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": SUBJECT_NAME,
                    "digest": {"sha256": hashlib.sha256(cls.canonical(predicate)).hexdigest()},
                }
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": predicate,
        }
        problems = Statements.validate(statement)
        if problems:
            raise CordonError("the scan statement does not validate: " + "; ".join(problems[:3]))
        return statement


class StatementReporter(BaseReporter):
    """`--format statement`: one canonical JSON line, the `scan/v1` statement."""

    id = "statement"
    media_type = "application/vnd.in-toto+json"
    file_extension = ".statement.json"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        yield ScanStatement.canonical(ScanStatement.of(result))
        yield b"\n"


__all__ = ["PREDICATE_TYPE", "STATEMENT_TYPE", "ScanStatement", "StatementReporter"]
