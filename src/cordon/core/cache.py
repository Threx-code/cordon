"""Incremental scan cache.

The cache exists so a second scan of a mostly-unchanged repository is fast
enough to run on every commit. Speed is a security property here: a guard that
costs noticeably more than a second gets bypassed, and a bypassed guard protects
nothing.

The key covers everything that could change a finding: the file's content, the
rule pack, the configuration, the detector versions, and the file's *context* --
its path, its language, and whether it executes at install time.

Any rule change, configuration change or engine upgrade invalidates every entry.
That is the only safe behaviour, and it is worth being explicit about why: a
stale cached "clean" is a false negative, and a false negative is the one error
class this project treats as unacceptable. Being over-eager to invalidate costs
a slower scan; being under-eager costs a missed payload.

Context belongs in the key for the same reason. Identical code is suspicious in
an application module and malicious in an install hook, so a content-only key
returns findings computed for a different file. That is not a stale result, it
is a wrong one, and it can move in either direction.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon.core.models import Finding
from cordon.version import SCHEMA_VERSION

if TYPE_CHECKING:
    from collections.abc import Sequence

CACHE_VERSION = 1
DEFAULT_CACHE_DIRNAME = ".cordon-cache"

MAX_ENTRY_BYTES = 1 * 1024 * 1024
"""Cap on a single cached result.

A file producing megabytes of findings is pathological, and caching it would
turn one hostile input into a permanent disk-space problem. Such a result is
simply not cached; the scan still works, it is only not accelerated.
"""


@dataclass(frozen=True, slots=True)
class CacheKey:
    """Everything that determines a file's findings.

    Content alone is not enough, and getting that wrong is the sharpest failure
    this cache can have. A finding depends on its *context* as well as its
    bytes: identical code is suspicious in an application module and malicious
    in an install hook, and a finding records the path it was found at. Keying
    on content alone therefore returns findings computed for a different file,
    which can promote an ordinary module to a malware finding or, worse, demote
    a real one.

    So the key includes the path, the install-time context and the language.
    That costs a cache miss on a rename, which is the correct trade: a rename
    changes every finding's location anyway, so the cached result would have
    been wrong to reuse.
    """

    content_hash: str
    rulepack_hash: str
    config_hash: str
    detector_signature: str
    path: str = ""
    in_install_hook: bool = False
    language: str = ""

    def digest(self) -> str:
        payload = "\x00".join(
            (
                str(CACHE_VERSION),
                str(SCHEMA_VERSION),
                self.content_hash,
                self.rulepack_hash,
                self.config_hash,
                self.detector_signature,
                self.path,
                "hook" if self.in_install_hook else "plain",
                self.language,
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ScanCache:
    """A content-addressed store of per-file findings.

    Deliberately a plain directory of JSON files rather than a database. There
    is no schema to migrate, no lock to contend on, corruption is confined to a
    single entry, and the whole thing can be deleted with `rm -rf` by anyone
    debugging it. A cache that is hard to inspect is a cache people stop
    trusting, and an untrusted cache gets disabled.
    """

    @staticmethod
    def default_cache_dir() -> Path:
        """Where the cache lives when the user has not chosen.

        Honours ``XDG_CACHE_HOME`` on Unix so it lands with everything else rather
        than in the middle of the repository being scanned, which would then have to
        be excluded and would appear in status output.
        """
        override = os.environ.get("CORDON_CACHE_DIR")
        if override:
            return Path(override)
        xdg = os.environ.get("XDG_CACHE_HOME")
        if xdg:
            return Path(xdg) / "cordon"
        return Path.home() / ".cache" / "cordon"

    @staticmethod
    def detector_signature(detectors: Sequence[Any]) -> str:
        """Identity of the detector set, so a version bump invalidates the cache.

        Sorted, because the set is what matters and not the order it was discovered
        in. Without this, upgrading a detector would silently reuse results produced
        by the previous version of it.
        """
        parts = sorted(f"{d.id}@{getattr(d, 'version', '0')}" for d in detectors)
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def finding_from_dict(data: dict[str, Any]) -> Finding:
        """Rebuild a finding from its serialised form.

        Reconstructed through the domain types rather than restored as a bare
        mapping, so a cached finding is indistinguishable from a freshly produced
        one everywhere downstream. That is what makes the equivalence test between a
        cold scan and a warm one meaningful.
        """
        from cordon.core.models import (
            Capability,
            Category,
            Confidence,
            Evidence,
            EvidenceKind,
            Explanation,
            Location,
            RedactionMode,
            RiskFactor,
            RiskScore,
            Severity,
            Suppression,
        )

        location = Location(**data["location"])

        evidence_data = dict(data["evidence"])
        metadata = evidence_data.pop("metadata", {})
        span = evidence_data.pop("span", None)
        evidence = Evidence(
            kind=EvidenceKind(evidence_data["kind"]),
            match_hash=evidence_data["match_hash"],
            redaction=RedactionMode(evidence_data["redaction"]),
            snippet=evidence_data.get("snippet"),
            span=tuple(span) if span else None,
            metadata=tuple(sorted((str(k), str(v)) for k, v in metadata.items())),
        )

        risk_data = data["risk"]
        risk = RiskScore(
            value=risk_data["value"],
            base=risk_data["base"],
            confidence_multiplier=risk_data["confidence_multiplier"],
            factors=tuple(
                RiskFactor(f["name"], f["points"], f["reason"])
                for f in risk_data.get("factors", ())
            ),
        )

        explanation_data = data["explanation"]
        explanation = Explanation(
            summary=explanation_data["summary"],
            matched_rule=explanation_data["matched_rule"],
            contributing=tuple(explanation_data.get("contributing", ())),
            escalations=tuple(explanation_data.get("escalations", ())),
        )

        suppression = None
        if "suppressed" in data:
            suppression = Suppression(**data["suppressed"])

        return Finding(
            rule_id=data["rule_id"],
            category=Category(data["category"]),
            severity=Severity.parse(data["severity"]),
            confidence=Confidence.parse(data["confidence"]),
            message=data["message"],
            location=location,
            evidence=evidence,
            remediation=data["remediation"],
            explanation=explanation,
            risk=risk,
            detector=data["detector"],
            rule_version=data.get("rule_version", "0.0.0"),
            rulepack=data.get("rulepack", "cordon-builtin"),
            references=tuple(data.get("references", ())),
            related=tuple(data.get("related", ())),
            occurrences=data.get("occurrences", 1),
            suppressed=suppression,
            capabilities=tuple(Capability(c) for c in data.get("capabilities", ())),
            fingerprint=data.get("fingerprint", ""),
        )

    def __init__(self, directory: Path | str | None = None, *, enabled: bool = True) -> None:
        self.directory = Path(directory) if directory else self.default_cache_dir()
        self.enabled = enabled
        self.hits = 0
        self.misses = 0
        self._writable: bool | None = None

    # -- Lookup ----------------------------------------------------------

    def get(self, key: CacheKey) -> tuple[Finding, ...] | None:
        """Return cached findings, or None.

        Any problem reading an entry is a miss rather than an error. A corrupt
        cache must degrade to a slower scan, never to a failed one: the cache is
        an optimisation and must not be able to break the thing it accelerates.
        """
        if not self.enabled:
            return None

        path = self._path(key)
        try:
            raw = path.read_bytes()
        except (OSError, ValueError):
            self.misses += 1
            return None

        try:
            payload = json.loads(raw)
            findings = tuple(ScanCache.finding_from_dict(f) for f in payload["findings"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # A corrupt entry is removed rather than left to fail repeatedly.
            path.unlink(missing_ok=True)
            self.misses += 1
            return None

        self.hits += 1
        return findings

    def put(self, key: CacheKey, findings: Sequence[Finding]) -> None:
        """Store findings for a key.

        Written atomically through a temporary file and a rename, so a
        concurrent reader never observes a half-written entry. Two scans running
        at once is normal -- a hook and an editor integration, or several CI
        jobs sharing a cache volume.
        """
        if not self.enabled or not self._ensure_writable():
            return

        payload = json.dumps(
            {
                "version": CACHE_VERSION,
                "findings": [f.to_dict() for f in findings],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        if len(payload) > MAX_ENTRY_BYTES:
            return

        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(handle, "wb") as out:
                    out.write(payload)
                Path(temporary).replace(path)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
        except OSError:
            # A read-only or full cache directory must not fail a scan.
            self._writable = False

    # -- Maintenance -----------------------------------------------------

    def clear(self) -> int:
        removed = 0
        if not self.directory.is_dir():
            return 0
        for entry in self.directory.rglob("*.json"):
            try:
                entry.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def size(self) -> tuple[int, int]:
        """Entry count and total bytes."""
        if not self.directory.is_dir():
            return 0, 0
        count = 0
        total = 0
        for entry in self.directory.rglob("*.json"):
            try:
                total += entry.stat().st_size
                count += 1
            except OSError:
                continue
        return count, total

    # -- Internals -------------------------------------------------------

    def _path(self, key: CacheKey) -> Path:
        digest = key.digest()
        # Two levels of fan-out. A single directory with a hundred thousand
        # entries is slow to enumerate on most filesystems and unpleasant to
        # inspect by hand.
        return self.directory / digest[:2] / digest[2:4] / f"{digest}.json"

    def _ensure_writable(self) -> bool:
        if self._writable is not None:
            return self._writable
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            probe = self.directory / ".write-probe"
            probe.write_bytes(b"")
            probe.unlink()
            self._writable = True
        except OSError:
            self._writable = False
        return self._writable


__all__ = [
    "CACHE_VERSION",
    "CacheKey",
    "ScanCache",
]
