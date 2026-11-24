"""A decision signed by the key the tenant's root delegated for deciding, checked offline against that root.

`decide()` signs nothing: the caller that holds a decider key signs the decision it was given, as a DSSE envelope of the
decision's canonical bytes. Whoever holds the tenant's pinned root and its delegation (a CLI offline, the control plane on
arrival) takes the decision only when a delegated `decider` key valid at the time signed exactly those bytes.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, ClassVar

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, Dsse
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer


class DecisionEnvelope:
    """Signs a decision and verifies a signed one."""

    TYPE: ClassVar[str] = "application/vnd.cordon.decision+json"
    ROLES: ClassVar[tuple[str, ...]] = ("decider",)

    @classmethod
    def sign(cls, decision: Decision, signer: Ed25519Signer) -> dict[str, Any]:
        body = decision.canonical_bytes()
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
    ) -> dict[str, Any]:
        """The decision document the envelope carries, or BundleError when no delegated decider key signed it."""
        keys = BundleChain.role_keys(root_public, delegation, tenant, now, cls.ROLES)
        document = json.loads(Dsse.verify(envelope, keys, payload_type=cls.TYPE))
        if not isinstance(document, dict):
            raise BundleError("the decision is not a document")
        return document
