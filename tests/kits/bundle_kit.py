"""A platform in a box for the execution plane's tests: a tenant root, a policy key it delegated, bundles it signs and chains.

Used by the local runtime, its store, the degrade modes and the pins tests. `Platform` plays the control plane (DSSE, Ed25519,
`prev_sha` chaining); `Kit` builds runtimes and compiled policies; `Upstream` is the control plane as the outbox sees it.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cordon_scanner.cloud.bundle_chain import BundleChain, Dsse
from cordon_scanner.cloud.local_runtime import LocalRuntime, NamePolicy
from cordon_scanner.cloud.local_store import LocalStore, Pending
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer

BUNDLE = "application/vnd.cordon.policy-bundle+json"
TENANT = "tenant-under-test"
SCOPE = "org:acme"
T0 = datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
ARTIFACT = ArtifactRef(
    kind="package",
    subject_id="pkg:npm/left-pad",
    digest=ArtifactDigests.of_bytes(b"left-pad"),
    ecosystem="npm",
    released_at="2026-06-01T00:00:00Z",
)


@dataclass
class Platform:
    """The tenant's control plane, as far as a client sees it: keys, a delegation, and the chain of bundles."""

    root: Ed25519Signer = field(default_factory=lambda: Ed25519Signer(Kit.seed("root")))
    policy_key: Ed25519Signer = field(default_factory=lambda: Ed25519Signer(Kit.seed("policy")))
    chain: list[dict[str, Any]] = field(default_factory=list)  # signed envelopes, oldest first
    payloads: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def sign(payload_type: str, document: dict[str, Any], signer: Ed25519Signer) -> dict[str, Any]:
        body = BundleChain.canonical(document)
        signature = signer.sign(Dsse.pae(payload_type, body))
        return {
            "payloadType": payload_type,
            "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [
                {
                    "keyid": Dsse.keyid(signer.public),
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    def loosening(
        self,
        *,
        relaxes: list[str],
        from_version: int,
        issued: datetime,
        expires: datetime,
        log_id: str = "log:entry-1",
        signer: Ed25519Signer | None = None,
        tenant: str = TENANT,
        scope: str = SCOPE,
    ) -> dict[str, Any]:
        """A signed loosening action: what a bundle that relaxes the policy carries, signed by the policy key unless told otherwise."""
        document = {
            "_type": "cordon.loosening/v1",
            "tenant": tenant,
            "scope": scope,
            "from_version": from_version,
            "relaxes": relaxes,
            "issued_at": issued.isoformat(),
            "expires_at": expires.isoformat(),
            "log_id": log_id,
        }
        return self.sign(
            "application/vnd.cordon.loosening+json", document, signer or self.policy_key
        )

    def delegation(self) -> dict[str, Any]:
        document = {
            "_type": "cordon.delegation/v1",
            "tenant": TENANT,
            "issued_at": T0.isoformat(),
            "keys": [
                {
                    "keyid": Dsse.keyid(self.policy_key.public),
                    "public": self.policy_key.public.hex(),
                    "role": "policy",
                    "not_before": (T0 - timedelta(days=1)).isoformat(),
                    "version": 1,
                }
            ],
        }
        return self.sign("application/vnd.cordon.delegation+json", document, self.root)

    def publish(
        self,
        policy: CompiledPolicy,
        *,
        issued: datetime,
        expires: datetime,
        carry_policy: bool = True,
        previous_sha: str | None = None,
        loosenings: list[dict[str, Any]] | None = None,
        lists: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        version = len(self.chain) + 1
        prev = previous_sha
        if prev is None:
            prev = BundleChain.payload_sha(self.payloads[-1]) if self.payloads else ""
        document: dict[str, Any] = {
            "tenant": TENANT,
            "scope": SCOPE,
            "version": version,
            "prev_sha": prev,
            "issued_at": issued.isoformat(),
            "expires_at": expires.isoformat(),
            "signer_keyid": Dsse.keyid(self.policy_key.public),
            "lists": {"deny": ["pkg:npm/evil"]} if lists is None else lists,
        }
        if loosenings:
            document["loosenings"] = loosenings
        if carry_policy:
            document["compiled_table"] = policy.to_json()
        envelope = self.sign("application/vnd.cordon.policy-bundle+json", document, self.policy_key)
        self.chain.append(envelope)
        self.payloads.append(document)
        return envelope


class Kit:
    @staticmethod
    def seed(label: str) -> bytes:
        return hashlib.sha256(label.encode()).digest()

    @staticmethod
    def compiled(
        version: int,
        expires: datetime,
        default: str = "allow",
        max_intel_age: int | None = None,
        on_incomplete: dict[str, str] | None = None,
        rules: list[dict[str, Any]] | None = None,
        serve_last_allow_hours: int | None = None,
    ) -> CompiledPolicy:
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/policy",
                    "version": version,
                    "scope": ["acme"],
                    "rules": rules or [],
                    "defaults": {
                        "default": default,
                        "on_incomplete": on_incomplete or {"*": "block", "ci": "warn"},
                        **({} if max_intel_age is None else {"max_intel_age": max_intel_age}),
                        **(
                            {}
                            if serve_last_allow_hours is None
                            else {"degrade": {"serve_last_allow_hours": serve_last_allow_hours}}
                        ),
                    },
                    "expires_at": expires.isoformat(),
                }
            )
        )

    @staticmethod
    def runtime(
        platform: Platform,
        store: LocalStore | None = None,
        names: NamePolicy | None = None,
        delegation: object | None = None,
    ) -> LocalRuntime:
        return LocalRuntime(
            root_public=platform.root.public,
            delegation=delegation if delegation is not None else platform.delegation(),
            tenant=TENANT,
            baseline=Kit.compiled(1, T0 + timedelta(days=3650), default="allow"),
            store=store,
            names=names,
        )

    @staticmethod
    def first(
        platform: Platform, *, default: str = "allow", lifetime: timedelta = timedelta(days=1)
    ) -> dict[str, Any]:
        expires = T0 + lifetime
        return platform.publish(Kit.compiled(1, expires, default), issued=T0, expires=expires)

    @staticmethod
    def ask(
        runtime: LocalRuntime, clock: datetime, point: str = "cli", environment: str = "production"
    ):
        return runtime.ask(
            point, ARTIFACT, EvidenceSet(), clock, environment=environment, scope_path=("acme",)
        )


class Upstream:
    """The control plane as the outbox sees it: keeps what it is sent once, by id, and can be made to fail on the nth call."""

    def __init__(self, fail_on: int | None = None) -> None:
        self.received: dict[str, bytes] = {}
        self.order: list[str] = []
        self.calls, self.fail_on = 0, fail_on

    def __call__(self, item: Pending) -> None:
        self.calls += 1
        if self.fail_on == self.calls:
            raise ConnectionError("the control plane is down")
        if item.id not in self.received:
            self.received[item.id] = item.body
            self.order.append(item.id)


class Things:
    @staticmethod
    def artifacts(count: int) -> list[ArtifactRef]:
        return [
            ArtifactRef(
                kind="package",
                subject_id=f"pkg:npm/package-{number}",
                digest=ArtifactDigests.of_bytes(f"package {number}".encode()),
                ecosystem="npm",
                released_at="2026-06-01T00:00:00Z",
            )
            for number in range(count)
        ]
