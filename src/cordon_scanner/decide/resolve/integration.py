"""BP-3-17: a third-party integration resolves to its subject and the digest of the contract it declares.

An integration is an external API, SaaS app or connector a tenant allows software or an agent to call (`int:<vendor>/<integration>`).
What it can do is written in the contract it declares: an OpenAPI document or a connector manifest. Given that contract the artifact is
its digest (`ArtifactDigests.of_contract` for a parsed document, `of_bytes` for the file exactly as served); an integration that
declares none cannot be bound to anything and is `unresolved` (`no_contract`), which `decide()` fails closed on (`R203`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.subjects import CanonicalIds, InvalidSubject, SubjectKind
from cordon_scanner.decide.resolve.resolution import Resolution


class IntegrationResolver:
    @classmethod
    def resolve(
        cls,
        vendor: str,
        integration: str,
        contract: Mapping[str, Any] | bytes | None = None,
        *,
        version: str | None = None,
    ) -> Resolution:
        kind = SubjectKind.INTEGRATION.value
        try:
            subject = CanonicalIds.canonical_id(
                SubjectKind.INTEGRATION, {"vendor": vendor, "integration": integration}
            )
        except InvalidSubject:
            return Resolution.failed(
                kind, Resolution.stand_in("int", f"{vendor}/{integration}"), "unparseable"
            )
        try:
            if isinstance(contract, bytes):
                digest = ArtifactDigests.of_bytes(contract) if contract else None
            elif contract is None:
                digest = None
            else:
                digest = ArtifactDigests.of_contract(contract)
        except ValueError:
            digest = None
        if digest is None:
            return Resolution.failed(kind, subject, "no_contract", version=version)
        return Resolution(
            kind=kind, subject_id=subject, status="resolved", version=version, digest=digest
        )


__all__ = ["IntegrationResolver"]
