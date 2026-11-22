"""What a resolver gives back: the subject, the version and the digest a decision binds to, or why there is none (rows BP-3-5, 3-13 to 3-16).

A tool names a thing loosely: `uses: actions/checkout@v4`, a skill folder, `npx -y @x/y`. A decision is about exact bytes (invariant I2),
so before it can be asked the name is resolved to `(subject id, version, digest)`. A resolver does that and never guesses: when it cannot,
it says `unresolved` with a reason from a fixed list, and `Resolution.evidence()` turns that into the `unresolved` fact `decide()` reads
(`R203`, at the level the policy sets in `defaults.unresolved`, `block` unless the tenant relaxed it: invariant I4, fail closed).

A resolver reaches the outside world only through a small interface it is handed (`ScmApi`, `Registry`), so the same code runs in the CLI,
a hook, the firewall and a test, and "the registry is down" is one exception, `SourceUnavailable`, that every resolver turns into the same
`unresolved` answer.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.private_names import PrivateNames
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet

if TYPE_CHECKING:
    from cordon_scanner.contracts.private_names import TenantKeys


class SourceUnavailable(Exception):
    """The SCM API or the registry could not be asked (no network, a timeout, a refusal, a server error): not a statement about the thing."""


class NotFound(Exception):
    """The source answered and has no such ref, package or version."""


@dataclass(frozen=True, slots=True)
class Resolution:
    """The result of resolving one name."""

    REASONS: ClassVar[tuple[str, ...]] = (
        "source_unreachable",  # the SCM API or registry could not be asked
        "not_found",  # it answered, and there is no such thing
        "unparseable",  # the reference is not of the form the resolver reads
        "not_a_registry_package",  # a git URL, a local path or another source the resolver does not fetch
        "local_action",  # a CI action inside the repository being scanned
        "local_command",  # an MCP server started from a program on the machine
        "remote_server",  # an MCP server reached over the network: its digest is its tool list at session start
        "unpinned_image",  # a container image named by tag only
        "symlink",  # a skill folder holding a symbolic link
        "unreadable",  # a file of a skill folder could not be read
        "too_large",  # a skill folder past the size or file count the resolver reads
        "unsupported_path",  # a file name the tree digest rule does not take
        "not_a_folder",  # the skill path is not a folder
    )

    kind: str
    subject_id: str
    status: str
    version: str | None = None
    digest: str | None = None
    commit: str | None = None
    registry: str | None = None
    ecosystem: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in ("resolved", "unresolved"):
            raise ValueError(f"status {self.status!r} is not resolved or unresolved")
        if self.status == "resolved" and (self.digest is None or self.reason is not None):
            raise ValueError("a resolved name has a digest and no reason")
        if self.status == "unresolved" and (
            self.digest is not None or self.reason not in self.REASONS
        ):
            raise ValueError(f"an unresolved name has no digest and a reason from {self.REASONS}")
        if self.digest is not None and not ArtifactDigests.is_digest(self.digest):
            raise ValueError(f"digest {self.digest!r} is not a sha256 digest")

    @property
    def resolved(self) -> bool:
        return self.status == "resolved"

    @classmethod
    def failed(
        cls, kind: str, subject_id: str, reason: str, version: str | None = None
    ) -> Resolution:
        return cls(
            kind=kind, subject_id=subject_id, status="unresolved", version=version, reason=reason
        )

    @staticmethod
    def stand_in(prefix: str, text: str) -> str:
        """The subject id of a reference that could not be read: a hash of what was written, never the text, so the same text
        is the same subject and nothing of it leaves."""
        return f"{prefix}:unparsed/{ArtifactDigests.of_bytes(text.encode('utf-8')).partition(':')[2][:32]}"

    def artifact(self, **facts: object) -> ArtifactRef:
        """The `ArtifactRef` to decide on: the digest is absent when the name did not resolve. `facts` are the rest of the ref
        (`released_at`, `ecosystem`, `namespace`, `tags`)."""
        if self.ecosystem is not None:
            facts.setdefault("ecosystem", self.ecosystem)
        return ArtifactRef(
            kind=self.kind,
            subject_id=self.subject_id,
            digest=self.digest,
            version=self.version,
            **facts,  # type: ignore[arg-type]
        )

    def evidence(self, evidence: EvidenceSet | None = None) -> EvidenceSet:
        """`evidence` (or an empty set) with the `unresolved` fact set when the name did not resolve."""
        base = evidence if evidence is not None else EvidenceSet()
        return base if self.resolved else replace(base, unresolved=True)

    def outbound_subject(
        self,
        tenant: str,
        keys: TenantKeys,
        *,
        private: bool | None = None,
        plain_opt_in: bool = False,
    ) -> str:
        """The form of the subject id that may leave the tenant (spec 22.2 Q1): the keyed hash for a private name, the plain id
        for a public one. A name is private when the caller says so, or when the registry it came from is not a public one."""
        is_private = (
            private if private is not None else PrivateNames.is_private(registry=self.registry)
        )
        return PrivateNames.outbound(
            self.subject_id, tenant, keys, private=is_private, plain_opt_in=plain_opt_in
        )


__all__ = ["NotFound", "Resolution", "SourceUnavailable"]
