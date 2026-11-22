"""The execution plane's local decision runtime (invariant I8, row BP-0-12): every point keeps deciding with the control plane down.

A point that holds a policy bundle the tenant's root signed (`bundle_chain.py` beside this file checks it offline) needs nothing from the
network to answer. The bundle's `compiled_table` is a compiled policy v2 (what the platform's `DecideEngine.compile_policy` writes,
merged down the tenant's chain) and its `lists` sit beside it. `LocalRuntime.ask` decides from the held compiled policy through `PointRuntime.ask`, the entry every
point uses. What happens when the bundle is too old is not decided here, it is the policy's: a compiled policy carries its own
expiry, and `decide()` answers `R202` at the level the policy sets for the call's environment (`defaults.on_incomplete`), so a
tenant's production gates block and its CI gates warn by the policy it published, and a change to that is a policy change.

Three things the runtime does itself, each failing closed:

* a bundle is taken only through `BundleChain.accept_chain` (every link verified, in order, all or nothing); one that does not
  verify, does not chain, or carries no compiled policy leaves the held bundle as it was;
* a bundle whose policy outlives the bundle is refused (the policy's own expiry is what `decide()` reads, so it must not be later
  than the bundle's);
* with no bundle held yet, the question is asked of the `baseline` policy with the policy bundle named as required evidence that
  is missing (`R200`), at the baseline's own level for incomplete evidence.

The runtime holds no clock and no network: the caller gives the time of the question, and refreshing is the caller's loop.

With a `LocalStore` (row BP-2-6) the runtime also keeps what it needs to start offline: `accept` keeps the bundle taken and `resume` takes
it again after a restart (verified again, expired or not: an expired bundle still decides, as `R202`); a decision is looked up by its
`inputs_digest` before it is made and kept after (equal inputs are equal decisions, so nothing kept is stale); each decision made
is queued for upload and `drain` sends the queue oldest first when the control plane is back; the age of the stored intel
snapshot is the `intel_age_s` of the question unless the caller gives one.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.decision.records import DecisionError, Instants
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.points import PointRuntime

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.cloud.local_store import Drained, LocalStore, Pending
    from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet

REQUIRED_BUNDLE: Final = "policy_bundle"
"""What `decide()` is told is missing while no bundle is held."""


class LocalRuntime:
    """Decides at one execution point from the policy bundle it holds."""

    def __init__(
        self,
        *,
        root_public: bytes,
        delegation: object,
        tenant: str,
        baseline: CompiledPolicy,
        store: LocalStore | None = None,
    ) -> None:
        baseline.verify()
        self._store = store
        self._root, self._delegation, self._tenant = root_public, delegation, tenant
        self._baseline = baseline
        self._held: dict[str, Any] | None = None
        self._policy: CompiledPolicy | None = None

    @property
    def held(self) -> dict[str, Any] | None:
        """The payload of the bundle held (verified when it was taken), or None."""
        return self._held

    @property
    def lists(self) -> dict[str, Any]:
        """The lists the held bundle carries beside its compiled policy (`lists`), or none."""
        found = (self._held or {}).get("lists")
        return dict(found) if isinstance(found, dict) else {}

    def accept(self, envelopes: Sequence[object], now: datetime) -> str:
        """Take the bundles the control plane sent since the one held, oldest first: `new` or `unchanged`.

        All or nothing: `BundleRefused` (by name) or `BundleError` leaves the held bundle as it was."""
        state, bundle = BundleChain.accept_chain(
            root_public=self._root,
            delegation=self._delegation,
            envelopes=list(envelopes),
            tenant=self._tenant,
            now=now,
            held=self._held,
        )
        if state == "new":
            self._policy = self._policy_of(bundle)
            self._held = bundle
            if self._store is not None:
                self._store.save_bundle([list(envelopes)[-1]])
        return state

    def resume(self, now: datetime) -> bool:
        """Take the bundle kept in the store, verified again (signature, key, tenant; its expiry is the policy's business, `R202`).

        False, holding nothing, when there is no store, nothing kept, a bundle already held, or a bundle that does not verify."""
        stored = self._store.load_bundle() if self._store is not None else None
        if not stored or self._held is not None:
            return False
        try:
            bundle = BundleChain.reverify(
                self._root, self._delegation, stored[-1], self._tenant, now
            )
            policy = self._policy_of(bundle)
        except BundleError:
            return False
        self._held, self._policy = bundle, policy
        return True

    def drain(self, send: Callable[[Pending], None]) -> Drained:
        """Send the uploads queued while offline, oldest first, stopping at the first that fails (see `LocalStore.drain`)."""
        if self._store is None:
            raise BundleError("no local store: nothing is queued")
        return self._store.drain(send)

    def ask(
        self,
        point: str,
        artifact: ArtifactRef,
        evidence: EvidenceSet,
        clock: datetime,
        *,
        environment: str,
        scope_path: tuple[str, ...] = (),
        actor: str = "human",
        relation: str = "direct",
        online: bool = False,
        intel_age_s: int | None = None,
    ) -> Decision:
        """The decision for `artifact` at `point`, from the bundle held at `clock`; never a network call."""
        if self._policy is None or self._held is None:
            asked = replace(
                evidence,
                required_missing=tuple(sorted({*evidence.required_missing, REQUIRED_BUNDLE})),
            )
            policy, bundle_age = self._baseline, None
        else:
            asked = evidence
            policy = self._policy
            bundle_age = max(
                0, int((clock - Instants.parse(self._held["issued_at"])).total_seconds())
            )
        if intel_age_s is None and self._store is not None:
            intel_age_s = self._intel_age(clock)
        store = self._store
        key = (
            None
            if store is None
            else PointRuntime.key(
                point,
                artifact,
                asked,
                policy,
                clock,
                environment=environment,
                scope_path=scope_path,
                actor=actor,
                relation=relation,
                online=online,
                bundle_age_s=bundle_age,
                intel_age_s=intel_age_s,
            )
        )
        if store is not None and key is not None:
            kept = store.cache_get(key)
            if kept is not None:
                return Decision.from_json(kept)
        decision = PointRuntime.ask(
            point,
            artifact,
            asked,
            policy,
            clock,
            environment=environment,
            scope_path=scope_path,
            actor=actor,
            relation=relation,
            online=online,
            bundle_age_s=bundle_age,
            intel_age_s=intel_age_s,
        )
        if store is not None and key is not None:
            store.cache_put(key, decision.to_json())
            store.enqueue("decision", decision.canonical_bytes())
        return decision

    def _intel_age(self, clock: datetime) -> int | None:
        """Seconds since the stored intel snapshot was issued, or None when the store has none (or a damaged one)."""
        snapshot = self._store.blob("intel", "snapshot") if self._store is not None else None
        if snapshot is None:
            return None
        return max(0, int((clock - Instants.parse(snapshot.issued_at)).total_seconds()))

    @staticmethod
    def _policy_of(bundle: dict[str, Any]) -> CompiledPolicy:
        """The compiled policy a bundle carries, checked: sealed, and not outliving the bundle."""
        document = bundle.get("compiled_table")
        if not isinstance(document, dict):
            raise BundleError("the bundle carries no compiled policy (compiled_table)")
        try:
            policy = CompiledPolicy.from_json(document)
            policy.verify()
        except DecisionError as problem:
            raise BundleError(f"the bundle's policy is not sound: {problem}") from problem
        if policy.expires_at is None:
            raise BundleError("the bundle's policy has no expiry")
        if Instants.parse(policy.expires_at) > Instants.parse(str(bundle["expires_at"])):
            raise BundleError("the bundle's policy outlives the bundle")
        return policy


__all__ = ["REQUIRED_BUNDLE", "LocalRuntime"]
