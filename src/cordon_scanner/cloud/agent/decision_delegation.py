"""The second link of the chain under a root the customer holds: the policy key delegates the decision keys (BP-15-15, scanner half).

With a platform-held root, the root's delegation names the decision keys itself: one link, read as it always was. With a root the
customer holds, the customer signs a delegation that names only the policy key (once per policy key); the policy key, platform-held,
then signs a decision delegation (`application/vnd.cordon.decision-delegation+json`, `cordon.decision-delegation/v1`) naming the decision
and workload keys, weekly. A decision is verified through both: the root's delegation names the policy key; the policy key signed the
decision delegation; the decision delegation names the key that signed the decision.

What is refused, each as a `BundleError`: a decision delegation not signed by a policy key the root's delegation names; not for this
tenant; not bound to this root (its `root_keyid`) and to this exact root delegation (its `root_issued_at`, both required); a sequence below
the highest held (an older one replayed; an equal one is the same document); a policy key not valid when it was issued; any key that is not a
decision role, whose `keyid` is not the sha256 of its public key, that has no zoned `not_before` and `valid_until`, or whose end is past the
policy key's own end. The keys the document delegates are then used only inside their own windows, whatever the document says of itself.

`issued_at` is not a freshness signal: the platform serves the same document, with the same `issued_at`, until the set of keys it names
changes. A key taken out of a later document stops being honoured at the latest when its own window ends, which is what bounds a device
that has not pulled."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.cloud.bundle_chain import POLICY_ROLES, BundleChain, BundleError, Dsse

if TYPE_CHECKING:
    from cordon_scanner.cloud.local_store import LocalStore

DECISION_DELEGATION_TYPE: Final = "application/vnd.cordon.decision-delegation+json"
DECISION_DELEGATION_SCHEMA: Final = "cordon.decision-delegation/v1"
DECISION_ROLES: Final = (
    "decision.cloud",
    "decision.cli",
    "decision.hook",
    "decision.firewall",
    "decision.gate",
)


class DecisionDelegation:
    PUBLIC: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
    #: The longest a delegated decision key may live (the platform's own bound: a workload key is enrolled for a year at most).
    MAX_WINDOW: ClassVar[timedelta] = timedelta(days=366)

    #: The local store's blob kind and name the accepted decision delegation is kept under.
    BLOB: ClassVar[str] = "decision-delegation"

    @classmethod
    def stored(cls, store: LocalStore) -> object:
        """The decision delegation last accepted and kept in `store`, or None. It is verified again whenever it is used."""
        kept = store.blob(cls.BLOB, cls.BLOB)
        if kept is None:
            return None
        try:
            return json.loads(kept.data)
        except ValueError:
            return None

    @classmethod
    def sequence_of(cls, envelope: object) -> int:
        """The sequence a kept envelope says it has (0 for none), read without verifying: only for what was verified before it was kept."""
        if envelope is None:
            return 0
        sequence = BundleChain.unverified_payload_document(envelope).get("sequence")
        return sequence if isinstance(sequence, int) and not isinstance(sequence, bool) else 0

    @classmethod
    def root_names_decision(cls, root_public: bytes, delegation: object, tenant: str) -> bool:
        """Whether the root's own delegation names a decision key: then the chain has one link and the decision delegation is not read."""
        keys = BundleChain.delegation(root_public, delegation, tenant=tenant)["keys"]
        return any(isinstance(k, dict) and k.get("role") in DECISION_ROLES for k in keys)

    @classmethod
    def accept(
        cls,
        root_public: bytes,
        delegation: object,
        tenant: str,
        envelope: object,
        *,
        min_sequence: int = 0,
    ) -> dict[str, Any]:
        """The decision delegation document, if every rule above holds; otherwise `BundleError`."""
        root_document = BundleChain.delegation(root_public, delegation, tenant=tenant)
        policy = {
            str(k["keyid"]): k
            for k in root_document["keys"]
            if isinstance(k, dict)
            and k.get("role") in POLICY_ROLES
            and isinstance(k.get("keyid"), str)
        }
        named = BundleChain.unverified_payload_document(envelope).get("policy_keyid")
        if not isinstance(named, str) or named not in policy:
            raise BundleError(
                "the decision delegation is not signed by a policy key the root delegated"
            )
        try:
            policy_public = bytes.fromhex(str(policy[named]["public"]))
        except (KeyError, ValueError) as problem:
            raise BundleError(
                "the root delegation holds a policy key that cannot be read"
            ) from problem
        body = Dsse.verify(envelope, {named: policy_public}, payload_type=DECISION_DELEGATION_TYPE)
        document = BundleChain._json(body, "the decision delegation")
        if document.get("_type") != DECISION_DELEGATION_SCHEMA or document.get("tenant") != tenant:
            raise BundleError("this decision delegation is not for this tenant")
        if document.get("root_keyid") != Dsse.keyid(root_public):
            raise BundleError("this decision delegation is not bound to this root")
        bound = document.get("root_issued_at")
        if not isinstance(bound, str) or bound != root_document.get("issued_at"):
            raise BundleError("this decision delegation is not bound to this root delegation")
        sequence = document.get("sequence")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < max(min_sequence, 0)
        ):
            raise BundleError("this decision delegation is older than the one already held")
        issued = cls._time(document.get("issued_at"), "when it was issued")
        if not BundleChain._valid_at(policy[named], issued):
            raise BundleError(
                "the policy key was not valid when this decision delegation was issued"
            )
        entries = document.get("keys")
        if not isinstance(entries, list):
            raise BundleError("the decision delegation lists no keys")
        ends = policy[named].get("valid_until")
        limit = cls._time(ends, "the policy key's end") if ends else None
        for entry in entries:
            cls._check(entry, limit)
        return document

    @classmethod
    def keys(
        cls, document: dict[str, Any], now: datetime, roles: tuple[str, ...]
    ) -> dict[str, bytes]:
        """The keys of `roles` the accepted decision delegation names that are valid at `now`, by key id."""
        return {
            str(entry["keyid"]): bytes.fromhex(str(entry["public"]))
            for entry in document["keys"]
            if entry["role"] in roles and BundleChain._valid_at(entry, now)
        }

    @classmethod
    def _check(cls, entry: object, limit: datetime | None) -> None:
        if not isinstance(entry, dict) or entry.get("role") not in DECISION_ROLES:
            raise BundleError("the decision delegation names a key that is not a decision key")
        public = entry.get("public")
        if not isinstance(public, str) or not cls.PUBLIC.fullmatch(public):
            raise BundleError("the decision delegation holds a key that cannot be read")
        if entry.get("keyid") != Dsse.keyid(bytes.fromhex(public)):
            raise BundleError("the decision delegation holds a key whose id is not its key's")
        start = cls._time(entry.get("not_before"), "a key's start")
        end = cls._time(entry.get("valid_until"), "a key's end")
        if end <= start:
            raise BundleError("the decision delegation holds a key that ends before it starts")
        if end - start > cls.MAX_WINDOW:
            raise BundleError(
                "the decision delegation delegates a key for longer than any decision key lives"
            )
        if limit is not None and end > limit:
            raise BundleError(
                "the decision delegation delegates a key past the policy key's own window"
            )

    @staticmethod
    def _time(value: object, what: str) -> datetime:
        try:
            moment = datetime.fromisoformat(str(value))
        except ValueError as problem:
            raise BundleError(f"the decision delegation's time {what} cannot be read") from problem
        if value is None or moment.tzinfo is None:
            raise BundleError(f"the decision delegation's time {what} has no zone")
        return moment


__all__ = [
    "DECISION_DELEGATION_SCHEMA",
    "DECISION_DELEGATION_TYPE",
    "DECISION_ROLES",
    "DecisionDelegation",
]
