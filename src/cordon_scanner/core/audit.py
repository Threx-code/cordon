"""The append-only record of what each scan did.

A report says what a scan found. An audit log says that a scan happened, under
which rules, and -- the part that matters -- what it was told to ignore. Those
are different questions asked by different people at different times, and a
report cannot answer the second one, because a suppressed finding is by
definition absent from it.

An auditor's first question about a security control is not "what did it find"
but "what was it configured not to look at". Answering that today means reading
every repository's configuration by hand and trusting that the copy being read
is the copy that ran. One line per scan, appended where the repository cannot
reach it, answers it directly.

Two rules govern what may be written here:

**Never file content.** The log records counts, rule identifiers, hashes and
the paths that were suppressed. It never records a matched line, because an
audit log is retained far longer than a report and read by more people, so it
is the worst possible place for the value a secrets rule just found.

**Never an unredacted remote.** The natural way to identify a repository is its
git remote, and a remote routinely carries a credential --
`https://x-access-token:ghp_...@github.com/org/repo.git` is what every CI
checkout looks like. Writing that verbatim would turn the audit log into the
credential store, so it goes through the same redactor a finding does.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.errors import ConfigError
from cordon_scanner.core.redact import Redactor
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from cordon_scanner.core.models import ScanResult


@dataclass(frozen=True, slots=True)
class AuditLog:
    """One JSON object per scan, appended to a file.

    JSON Lines rather than a JSON array, because an array has to be rewritten to
    append to it and a partially rewritten array is unreadable. A line-delimited
    file survives a truncated write with the loss of one record, and every log
    shipper already understands it.
    """

    path: Path

    MAX_SUPPRESSIONS = 200
    """Cap on recorded suppressions.

    A repository can declare an unbounded number, and an audit log that a scan
    target can grow without limit is a disk-exhaustion primitive against the
    machine collecting it. Truncation is recorded in the line itself, so a
    reader is never silently shown a partial list.
    """

    @classmethod
    def prepare(cls, path: str | Path) -> AuditLog:
        """Check the destination before the scan rather than after it.

        An audit log that turns out to be unwritable once the work is finished
        leaves the operator with a scan they cannot attest to. Failing at the
        point the flag is read makes that a corrected command line instead.
        """
        target = Path(path).expanduser()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise ConfigError(
                f"audit log {target} cannot be written: {exc}",
                hint="Point --audit-log at a writable path, or omit it.",
            ) from exc
        return cls(path=target)

    def record(
        self,
        result: ScanResult,
        *,
        exit_code: int,
        target_kind: str,
        policy: str | None = None,
    ) -> None:
        """Append one line describing a completed scan."""
        line = json.dumps(
            self.entry(result, exit_code=exit_code, target_kind=target_kind, policy=policy),
            separators=(",", ":"),
            sort_keys=True,
        )
        # Opened per record and closed immediately. A long-lived handle would
        # hold the file across a scan that may take minutes, and a single
        # `write` of one short line is atomic enough on every platform this
        # runs on that concurrent scans interleave records rather than corrupt
        # them.
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def entry(
        self,
        result: ScanResult,
        *,
        exit_code: int,
        target_kind: str,
        policy: str | None = None,
    ) -> dict[str, Any]:
        """Build the record. Separated from writing so it can be tested."""
        from cordon_scanner.core.models import Severity

        counts: dict[str, int] = {}
        for finding in result.findings:
            if finding.is_suppressed:
                counts["suppressed"] = counts.get("suppressed", 0) + 1
                continue
            key = str(finding.severity)
            counts[key] = counts.get(key, 0) + 1
        for severity in Severity:
            counts.setdefault(str(severity), 0)
        counts.setdefault("suppressed", 0)

        suppressed = [f for f in result.findings if f.is_suppressed]
        applied = [
            {
                "rule": f.rule_id,
                "path": f.location.path,
                # The recorded reason, which is the field an auditor reads
                # first: a suppression with no justification is one nobody can
                # evaluate.
                "justification": (f.suppressed.justification if f.suppressed else "") or "",
                "approved_by": (f.suppressed.approved_by if f.suppressed else "") or "",
                "expires": (f.suppressed.expires if f.suppressed else "") or "",
            }
            for f in suppressed[: self.MAX_SUPPRESSIONS]
        ]

        repository = result.repository
        remote = getattr(repository, "remote", None) if repository else None
        revision = getattr(repository, "revision", None) if repository else None

        entry: dict[str, Any] = {
            "ts": _timestamp(),
            "event": "scan.complete",
            "cordon_version": __version__,
            "rulepack": f"cordon-builtin@{result.rulepack_version}",
            "rulepack_sha256": result.rulepack_hash,
            "config_sha256": result.config_hash,
            "policy": policy or "",
            "target_kind": target_kind,
            # Redacted. A git remote routinely carries a credential, and an
            # audit log is retained longer and read by more people than a
            # report, so writing one verbatim makes this the credential store.
            "repo": Redactor.mask(str(remote)) if remote else "",
            "revision": str(revision) if revision else "",
            "files_scanned": result.stats.files_scanned,
            "findings": counts,
            "suppressions_applied": applied,
            "suppressions_truncated": max(0, len(suppressed) - self.MAX_SUPPRESSIONS),
            "complete": result.complete,
            "duration_ms": result.stats.duration_ms,
            "exit_code": exit_code,
        }
        return entry


def _timestamp() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["AuditLog"]
