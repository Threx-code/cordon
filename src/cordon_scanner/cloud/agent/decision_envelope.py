"""A decision signed as the platform takes it, checked offline against the tenant's root.

`decide()` signs nothing: the caller that holds a decision key signs the decision it was given. The signed bytes are an in-toto
Statement v1 whose subject is the artifact (its name and its digest keyed by algorithm) and whose predicate is the decision
(`decision/v1`), in a DSSE envelope of type `application/vnd.in-toto+json`: the shape `POST /v1/evidence` verifies. The key must
be one the tenant's root delegated for deciding (`decision.cli`, `.hook`, `.firewall`, `.gate` or `.cloud`) and valid at the time.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, ClassVar

from cordon_scanner.cloud.agent.decision_delegation import DecisionDelegation
from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, Dsse
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer


class DecisionEnvelope:
    """Signs a decision and verifies a signed one."""

    TYPE: ClassVar[str] = "application/vnd.in-toto+json"
    STATEMENT: ClassVar[str] = "https://in-toto.io/Statement/v1"
    PREDICATE: ClassVar[str] = "https://cordonscan.com/decision/v1"
    ROLES: ClassVar[tuple[str, ...]] = (
        "decision.cloud",
        "decision.cli",
        "decision.hook",
        "decision.firewall",
        "decision.gate",
    )

    @classmethod
    def statement(cls, decision: Decision, subject_id: str, digest: str) -> dict[str, Any]:
        """The in-toto Statement for a decision about the artifact `subject_id` whose digest is `<algorithm>:<hex>`."""
        algorithm, _, value = digest.partition(":")
        return {
            "_type": cls.STATEMENT,
            "subject": [{"name": subject_id, "digest": {algorithm: value}}],
            "predicateType": cls.PREDICATE,
            "predicate": decision.to_json(),
        }

    @classmethod
    def sign(
        cls, decision: Decision, signer: Ed25519Signer, *, subject_id: str, digest: str
    ) -> dict[str, Any]:
        body = ArtifactDigests.canonical_json(cls.statement(decision, subject_id, digest))
        signature = signer.sign(Dsse.pae(cls.TYPE, body))
        return {
            "payloadType": cls.TYPE,
            "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [
                {
                    "keyid": Dsse.keyid(signer.public),
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    @classmethod
    def verify(
        cls,
        envelope: object,
        *,
        root_public: bytes,
        delegation: object,
        tenant: str,
        now: datetime,
        decision_delegation: object = None,
        min_sequence: int = 0,
    ) -> dict[str, Any]:
        """The statement the envelope carries, or BundleError when no delegated decision key signed it.

        A root that names a decision key itself is the one-link chain and `decision_delegation` is not read. A root that names none (one
        the customer holds) leaves the decision keys to the decision delegation the policy key signed (`DecisionDelegation`), whose
        sequence must not be below `min_sequence`, the highest the verifier holds."""
        keys = BundleChain.role_keys(root_public, delegation, tenant, now, cls.ROLES)
        if decision_delegation is not None and not DecisionDelegation.root_names_decision(
            root_public, delegation, tenant
        ):
            accepted = DecisionDelegation.accept(
                root_public, delegation, tenant, decision_delegation, min_sequence=min_sequence
            )
            keys = {**keys, **DecisionDelegation.keys(accepted, now, cls.ROLES)}
        document = json.loads(Dsse.verify(envelope, keys, payload_type=cls.TYPE))
        if not isinstance(document, dict) or document.get("_type") != cls.STATEMENT:
            raise BundleError("the payload is not an in-toto statement")
        return document
