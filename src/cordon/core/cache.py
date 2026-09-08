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

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon.core.models import Finding
from cordon.version import SCHEMA_VERSION

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

CACHE_VERSION = 2
"""Bumped when the on-disk format changes.

Version 2 added the MAC. Entries written by version 1 carry no `mac` field and
are rejected by verification, which is the correct outcome: they are exactly as
trustworthy as an entry an attacker wrote.
"""

KEY_NAME = ".cordon-cache-key"
"""Per-machine HMAC key, created 0600 on first use.

Not a secret worth much on its own. Its job is to make a cache entry unforgeable
by anyone who cannot already write the user's files -- and anybody who can do
that can edit the source being scanned, at which point the cache is not the weak
link."""
DEFAULT_CACHE_DIRNAME = ".cordon-cache"

MAX_ENTRY_BYTES = 1 * 1024 * 1024

MAX_ENTRY_AGE_DAYS = 30
"""How long an entry stays useful.

A file not scanned in a month is one whose content has almost certainly changed,
so the entry would miss anyway. Without eviction the cache grew without bound,
which on a shared CI volume is a slow disk-space failure nobody attributes to
the scanner."""
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
        """Where cache *entries* live when the user has not chosen.

        Honours ``XDG_CACHE_HOME`` on Unix so it lands with everything else rather
        than in the middle of the repository being scanned, which would then have to
        be excluded and would appear in status output.

        Environment-directed, and deliberately so -- CI needs to point this at a
        restorable path. See `key_dir`, which is not, and why.
        """
        override = os.environ.get("CORDON_CACHE_DIR")
        if override:
            return Path(override)
        xdg = os.environ.get("XDG_CACHE_HOME")
        if xdg:
            return Path(xdg) / "cordon"
        return Path.home() / ".cache" / "cordon"

    @staticmethod
    def key_dir() -> Path:
        """Where the authentication key lives. Never environment-directed.

        The key used to live beside the entries, which meant one variable
        decided both. Anything that can set a variable in the build -- an `env:`
        block in the scanned repository's own workflow, a `.env` a Makefile
        sources, a compromised profile -- could point `CORDON_CACHE_DIR` at a
        directory it had already filled with entries and a key of its own. Every
        input to a cache key is public or attacker-computable, so it could
        compute the exact path for each of its files, sign `{"findings": []}`
        with its own key, and have all of it verify. The scan then reports
        nothing and exits 0, which is the worst outcome this tool has: not a
        missed detection but a confident all-clear over a repository that was
        never examined.

        Separating the two removes the attack without removing the feature.
        Entries may live anywhere; the key is derived from the user's home
        directory, so entries written under a key the attacker chose fail
        verification and become ordinary cache misses. The scan is slower and
        correct.

        `XDG_CACHE_HOME` is ignored here for the same reason -- it is a variable
        too, and honouring it would leave the redirect available under a
        different name. A user who has moved their cache still gets a working
        cache; only this one file stays put.
        """
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
            always_report=bool(data.get("always_report", False)),
            fingerprint=data.get("fingerprint", ""),
        )

    def __init__(self, directory: Path | str | None = None, *, enabled: bool = True) -> None:
        self.directory = Path(directory) if directory else self.default_cache_dir()
        self.enabled = enabled
        self.hits = 0
        self.misses = 0
        self._writable: bool | None = None
        self._key_material: bytes | None = None

    # -- Lookup ----------------------------------------------------------

    def get(self, key: CacheKey) -> tuple[Finding, ...] | None:
        """Return cached findings, or None.

        Any problem reading an entry is a miss rather than an error. A corrupt
        cache must degrade to a slower scan, never to a failed one: the cache is
        an optimisation and must not be able to break the thing it accelerates.

        An entry whose MAC does not verify is treated the same way. Every input
        to the cache key is public or attacker-computable -- the content hash is
        of the attacker's own file, the rulepack hash and detector signature are
        fixed per release, and the config hash is derivable from published
        defaults -- so anyone who can write to the cache directory can compute
        the exact path for a file they are about to commit and leave
        `{"findings": []}` there. Without authentication that is a permanent,
        silent, total bypass for chosen files.
        """
        if not self.enabled:
            return None

        path = self._path(key)
        try:
            # Bounded before reading. MAX_ENTRY_BYTES was enforced on write
            # only, so a planted multi-gigabyte entry was pulled entirely into
            # memory before anything verified it.
            if path.stat().st_size > MAX_ENTRY_BYTES:
                self.misses += 1
                return None
            raw = path.read_bytes()
        except (OSError, ValueError):
            self.misses += 1
            return None

        try:
            payload = json.loads(raw)
            if not self._verify(payload, key):
                # Not deleted. An unverified entry may belong to another user
                # sharing the directory, and removing it would turn a read
                # into a destructive act on somebody else's data.
                self.misses += 1
                return None
            findings = tuple(ScanCache.finding_from_dict(f) for f in payload["findings"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # A corrupt entry is removed rather than left to fail repeatedly.
            path.unlink(missing_ok=True)
            self.misses += 1
            return None

        self.hits += 1
        return findings

    # -- Authentication --------------------------------------------------

    def _secret(self) -> bytes | None:
        """The per-machine key entries are authenticated with.

        Generated on first use, stored `0600` beside the cache. Its only job is
        to make an entry unforgeable by anyone who cannot already read the
        user's files -- at which point they can edit the source being scanned
        and the cache is not the weak link.

        Returns None when the key can neither be read nor created, and callers
        then treat every entry as a miss. Failing to a slower scan is correct;
        failing to an unauthenticated one is not.
        """
        if self._key_material is not None:
            return self._key_material or None

        path = self.key_dir() / KEY_NAME
        try:
            material = path.read_bytes()
            if len(material) >= 32 and self._key_is_private(path):
                self._key_material = material
                return material
            if len(material) >= 32:
                # Readable by somebody else, so it is not a secret. Replaced
                # rather than used: an attacker who can read the key can forge
                # an entry for a file they are about to commit, and every input
                # to the cache path is public, so they can compute exactly where
                # to put it. A restored CI cache artefact or a shared volume is
                # how a directory arrives with loose permissions.
                with contextlib.suppress(OSError):
                    path.unlink()
        except OSError:
            pass

        try:
            key_directory = self.key_dir()
            key_directory.mkdir(parents=True, exist_ok=True)
            # 0700 on the directory, so another user cannot read the key or
            # plant entries even if they can reach the path.
            with contextlib.suppress(OSError):
                key_directory.chmod(0o700)
            self.directory.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                self.directory.chmod(0o700)
            material = secrets.token_bytes(32)
            handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(handle, material)
            finally:
                os.close(handle)
            self._key_material = material
            return material
        except FileExistsError:
            # Another process created it between the read and the write.
            try:
                self._key_material = path.read_bytes()
                return self._key_material or None
            except OSError:
                self._key_material = b""
                return None
        except OSError:
            self._key_material = b""
            return None

    @staticmethod
    def _key_is_private(path: Path) -> bool:
        """Whether the key file is owned by this user and readable only by them.

        The MAC design was right and the read path did not check either, so a
        cache directory that already existed with looser permissions handed the
        key to anyone who could read it. `chmod(0o700)` ran only on the creation
        branch, which is exactly the branch that does not execute when the
        directory is already there.
        """
        if os.name == "nt":  # pragma: no cover - POSIX permissions only
            return True
        try:
            info = path.stat()
        except OSError:
            return False
        return info.st_uid == os.getuid() and not info.st_mode & 0o077

    def _mac(self, body: bytes, key: CacheKey) -> str | None:
        """MAC over the payload *and* the key it is filed under.

        Binding the key in stops an entry being valid at a different path: a
        genuine `{"findings": []}` for a benign file could otherwise be copied
        onto the cache path of a malicious one.
        """
        secret = self._secret()
        if secret is None:
            return None
        return hmac.new(secret, key.digest().encode("ascii") + b"|" + body, "sha256").hexdigest()

    def _verify(self, payload: Any, key: CacheKey) -> bool:
        if not isinstance(payload, dict):
            return False
        recorded = payload.get("mac")
        body = payload.get("findings")
        if not isinstance(recorded, str) or body is None:
            return False
        expected = self._mac(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"), key
        )
        if expected is None:
            return False
        return hmac.compare_digest(expected, recorded)

    def put(self, key: CacheKey, findings: Sequence[Finding]) -> None:
        """Store findings for a key.

        Written atomically through a temporary file and a rename, so a
        concurrent reader never observes a half-written entry. Two scans running
        at once is normal -- a hook and an editor integration, or several CI
        jobs sharing a cache volume.
        """
        if not self.enabled or not self._ensure_writable():
            return

        body = [f.to_dict() for f in findings]
        mac = self._mac(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"), key
        )
        if mac is None:
            # No key material means entries cannot be authenticated, and an
            # unauthenticated entry is worse than none at all.
            return

        payload = json.dumps(
            {"version": CACHE_VERSION, "findings": body, "mac": mac},
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

    def prune(self, *, max_age_days: int = MAX_ENTRY_AGE_DAYS) -> int:
        """Remove entries older than `max_age_days`. Returns the count removed.

        The cache had `clear` and `size` and no eviction at all, so a long-lived
        CI cache volume accumulated up to a megabyte per unique
        (content, config, rulepack) tuple, indefinitely. Age rather than a size
        cap, because the useful entries are the recent ones: a file that has not
        been scanned in a month is one whose content has almost certainly
        changed.
        """
        if not self.directory.is_dir():
            return 0
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        for entry in self._entry_files():
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                # A cache that cannot be pruned is not a scan failure.
                continue
        return removed

    def _entry_files(self) -> Iterator[Path]:
        """Every cache entry, without following symlinked directories.

        `Path.rglob` descends into them on Python before 3.13, and both callers
        then `unlink()` what they find -- so a symlink planted in the cache
        directory turned maintenance into arbitrary deletion of `*.json`
        anywhere the user can write.
        """
        for parent, dirnames, filenames in os.walk(self.directory, followlinks=False):
            dirnames[:] = [d for d in dirnames if not Path(parent, d).is_symlink()]
            for name in filenames:
                candidate = Path(parent, name)
                if name.endswith(".json") and not candidate.is_symlink():
                    yield candidate

    def clear(self) -> int:
        removed = 0
        if not self.directory.is_dir():
            return 0
        for entry in self._entry_files():
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
