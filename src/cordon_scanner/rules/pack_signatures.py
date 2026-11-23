"""Two signatures on every delivered rule pack, checked before the pack is read.

A promoted pack's index entry carries `decision` (the gate's decision body), `statement` (what the pack signer vouches for) and
`signatures` with a `gate` and a `pack` signature. A scanner that requires two (`FeedFloor.REQUIRE_PACK_SIGNATURES`) takes the
pack only when all of this holds: the gate signature verifies, over the canonical bytes of `decision`, against a pinned lab key;
the decision's candidate digest is the sha256 of the pack file; the statement names the sha256 of the canonical decision and of
the pack file; the pack signature verifies, over the canonical bytes of `statement`, against a pinned pack-signer key (a list of
its own, so one key cannot satisfy both); the statement's enforcement is the index entry's; and a block carries an approval of the
same pack text with an id. Fewer than both signatures, or any check failing, refuses the pack with the reason.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, ClassVar

from cordon_scanner.intel.provenance import _ed25519
from cordon_scanner.rules.warn_list import WarnList


class PackSignatures:
    LAB_KEYS: ClassVar[tuple[str, ...]] = ()
    """Hex Ed25519 public keys of the lab whose gate decisions are accepted; pinned at the release build."""

    PACK_KEYS: ClassVar[tuple[str, ...]] = ()
    """Hex Ed25519 public keys of the pack signer, a list apart from the lab's; pinned at the release build."""

    @staticmethod
    def canonical(document: Any) -> bytes:
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def verifies(cls, signature: Any, pinned: tuple[str, ...], message: bytes) -> bool:
        if not isinstance(signature, dict):
            return False
        public, sig = signature.get("public"), signature.get("sig")
        if not isinstance(public, str) or not isinstance(sig, str) or public not in pinned:
            return False
        try:
            return bool(_ed25519.Ed25519.verify(bytes.fromhex(public), message, bytes.fromhex(sig)))
        except ValueError:
            return False

    @classmethod
    def warn_problem(cls, entry: dict[str, Any], statement: dict[str, Any]) -> str | None:
        """Why a warning list is not to be believed: the entry has one the statement does not carry equally, or it is not of the form."""
        if entry.get("warn") is None and statement.get("warn") is None:
            return None
        if entry.get("warn") != statement.get("warn"):
            return "the entry's warning list is not the one the pack signer signed"
        if WarnList.parse(entry.get("warn")) is None:
            return "the warning list is not of the form"
        return None

    @classmethod
    def problem(cls, entry: dict[str, Any], pack_bytes: bytes) -> str | None:
        """Why the pack of this index entry is refused for its signatures, or None when both hold and every clause is met."""
        decision, statement, signatures = (
            entry.get("decision"),
            entry.get("statement"),
            entry.get("signatures"),
        )
        if not (
            isinstance(decision, dict)
            and isinstance(statement, dict)
            and isinstance(signatures, dict)
        ):
            return "it does not carry both signatures (a decision, a statement and signatures)"
        if "gate" not in signatures or "pack" not in signatures:
            return "it does not carry both the gate and the pack signature"
        canonical = cls.canonical(decision)
        if not cls.verifies(signatures["gate"], cls.LAB_KEYS, canonical):
            return "the gate signature does not verify against a pinned lab key"
        text = cls.digest(pack_bytes)
        if decision.get("candidate_digest") != text:
            return "the gate decision is about other pack text"
        if statement.get("decision_sha256") != cls.digest(canonical):
            return "the statement is about another decision"
        if statement.get("yaml_sha256") != text:
            return "the statement is about other pack text"
        if not cls.verifies(signatures["pack"], cls.PACK_KEYS, cls.canonical(statement)):
            return "the pack signature does not verify against a pinned pack-signer key"
        if statement.get("enforcement") != entry.get("enforcement"):
            return "the statement's enforcement is not the index entry's"
        listed = cls.warn_problem(entry, statement)
        if listed is not None:
            return listed
        if entry.get("enforcement") == "block":
            approval = statement.get("approval")
            if (
                not isinstance(approval, dict)
                or approval.get("yaml_sha256") != text
                or not approval.get("id")
            ):
                return "a block pack carries no approval of this pack text"
        return None


__all__ = ["PackSignatures"]
