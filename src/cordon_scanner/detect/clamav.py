"""Hand file bytes to a local ClamAV daemon. Optional, off by default, and it says whether it ran.

Cordon's own detection is behavioural: what code does at install time, what an agent config
grants. ClamAV's is signature-based: known malware families, including in binaries and documents
Cordon only inventories. The two answer different questions, so an organisation that already
runs clamd can have both in one report.

Only a local daemon is ever contacted -- a Unix socket, or TCP on a loopback address -- so no file
leaves the machine. The bytes are streamed with clamd's `INSTREAM` command; nothing is written to
disk for it to read. At the start of a scan the daemon is asked for its version and the result is
reported (`OPERATIONAL.CLAMAV.STATUS`); if it cannot be reached the scan is marked incomplete
(`OPERATIONAL.CLAMAV.UNAVAILABLE`), because a check the operator asked for and did not get is
coverage lost.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import urllib.parse
from typing import TYPE_CHECKING, Final

from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, RepositoryUnit
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

SIGNATURE_RULE: Final = "MALWARE.CLAMAV.SIGNATURE.001"
STATUS_RULE: Final = "OPERATIONAL.CLAMAV.STATUS"
UNAVAILABLE_RULE: Final = "OPERATIONAL.CLAMAV.UNAVAILABLE"
CHUNK: Final = 64 * 1024
TIMEOUT_SECONDS: Final = 30.0
REFERENCE: Final = "https://docs.clamav.net/manual/Usage/Scanning.html"


class ClamdError(Exception):
    """clamd could not be asked. Safe to show."""


class Clamd:
    """The clamd protocol: a local daemon over a Unix socket or loopback TCP."""

    @staticmethod
    def connect(address: str) -> socket.socket:
        """A connection to clamd at a Unix socket path or a loopback `tcp://host:port`."""
        if address.startswith("tcp://"):
            parsed = urllib.parse.urlsplit(address)
            host = parsed.hostname or ""
            try:
                loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not loopback or not parsed.port:
                raise ClamdError("clamd over TCP must be on a loopback address with a port")
            try:
                return socket.create_connection((host, parsed.port), timeout=TIMEOUT_SECONDS)
            except OSError as exc:
                raise ClamdError(
                    f"clamd at {host}:{parsed.port} could not be reached ({type(exc).__name__})"
                ) from exc
        if not hasattr(socket, "AF_UNIX"):
            raise ClamdError("Unix sockets are not available here; use tcp://127.0.0.1:3310")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(TIMEOUT_SECONDS)
        try:
            connection.connect(address)
        except OSError as exc:
            connection.close()
            raise ClamdError(
                f"clamd at {address} could not be reached ({type(exc).__name__})"
            ) from exc
        return connection

    @staticmethod
    def _reply(connection: socket.socket) -> str:
        data = b""
        while not data.endswith(b"\x00"):
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 1 << 16:
                break
        return data.rstrip(b"\x00").decode("utf-8", "replace").strip()

    @staticmethod
    def version(address: str) -> str:
        with Clamd.connect(address) as connection:
            connection.sendall(b"zVERSION\x00")
            return Clamd._reply(connection)

    @staticmethod
    def scan_bytes(address: str, data: bytes) -> str | None:
        """The signature name clamd reports for these bytes, or None when it reports none."""
        with Clamd.connect(address) as connection:
            connection.sendall(b"zINSTREAM\x00")
            for start in range(0, len(data), CHUNK):
                piece = data[start : start + CHUNK]
                connection.sendall(struct.pack(">I", len(piece)) + piece)
            connection.sendall(struct.pack(">I", 0))
            answer = Clamd._reply(connection)
        if answer.endswith(" FOUND"):
            return answer.removeprefix("stream:").removesuffix(" FOUND").strip()
        if answer.endswith("OK"):
            return None
        raise ClamdError(f"clamd answered: {answer[:200]}")


class ClamavDetector(BaseDetector):
    id = "clamav"
    version = "0.1.0"
    operator_enabled = True
    """Runs only when the operator names a daemon, so a default scan never exercises it; it is
    exercised against a protocol-accurate fake in tests/unit/test_clamav.py."""
    categories = frozenset({Category.MALICIOUS, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, repository=True)

    def __init__(self) -> None:
        self._failed = False

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.config.clamav)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=SIGNATURE_RULE,
                title="ClamAV recognises the file as malware",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.MALICIOUS,
                detector=ClamavDetector.id,
                message="The local ClamAV daemon matched this file against a malware signature.",
                references=(REFERENCE,),
                remediation="Remove the file and find out how it entered the repository.",
            ),
            DeclaredRule(
                id=STATUS_RULE,
                title="ClamAV examined the scan's files",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=ClamavDetector.id,
                message="The files in this scan were also handed to the local ClamAV daemon named here.",
                references=(REFERENCE,),
                remediation="None needed.",
            ),
            DeclaredRule(
                id=UNAVAILABLE_RULE,
                title="ClamAV was asked for and could not be used",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=ClamavDetector.id,
                message="The scan was asked to use ClamAV and could not reach it, so no file was checked by it.",
                references=(REFERENCE,),
                remediation="Start clamd, or point --clamav at its socket.",
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        address = ctx.config.clamav or ""
        if isinstance(unit, RepositoryUnit):
            if self._failed:
                return ()  # already reported by the file that found clamd gone
            try:
                engine = Clamd.version(address)
            except (ClamdError, OSError) as exc:
                self._failed = True
                return [
                    self._operational(
                        UNAVAILABLE_RULE, f"ClamAV was requested and could not be used: {exc}.", ctx
                    )
                ]
            return [
                self._operational(
                    STATUS_RULE, f"Files were also checked by ClamAV ({engine}).", ctx
                )
            ]
        if not isinstance(unit, FileUnit) or self._failed:
            return ()
        try:
            signature = Clamd.scan_bytes(address, unit.content.raw)
        except (ClamdError, OSError) as exc:
            self._failed = True
            return [
                self._operational(
                    UNAVAILABLE_RULE, f"ClamAV stopped answering during the scan: {exc}.", ctx
                )
            ]
        if signature is None:
            return ()
        return [
            Finding(
                rule_id=SIGNATURE_RULE,
                category=Category.MALICIOUS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                message=f"ClamAV identifies this file as {signature}.",
                location=Location(path=unit.content.path, project=unit.project),
                evidence=Evidence(
                    kind=EvidenceKind.HASH,
                    match_hash=Evidence.hash_bytes(
                        f"{signature}:".encode() + unit.content.raw[:65536]
                    ),
                    redaction=RedactionMode.HASH_ONLY,
                    metadata=(("clamav_signature", signature),),
                ),
                remediation="Remove the file and find out how it entered the repository.",
                explanation=Explanation(
                    summary=f"clamd INSTREAM: {signature} FOUND", matched_rule=SIGNATURE_RULE
                ),
                risk=ctx.scorer.score(Severity.CRITICAL, Confidence.HIGH),
                detector=self.id,
                references=(REFERENCE,),
            )
        ]

    def _operational(self, rule_id: str, message: str, ctx: ScanContext) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path="."),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{message}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="Start clamd, or point --clamav at its socket."
            if rule_id == UNAVAILABLE_RULE
            else "None needed.",
            explanation=Explanation(summary=message, matched_rule=rule_id),
            risk=ctx.scorer.score(Severity.INFO, Confidence.CONFIRMED),
            detector=self.id,
            references=(REFERENCE,),
        )


__all__ = ["ClamavDetector", "Clamd", "ClamdError"]
