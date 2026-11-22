"""The execution plane's local decision runtime (invariant I8, row BP-0-12): every point keeps deciding with the control plane down.

A point that holds a policy bundle the tenant's root signed (`bundle_chain.py` beside this file checks it offline) needs nothing from the
network to answer: `LocalRuntime.ask` decides from the held bundle's compiled policy through `PointRuntime.ask`, the entry every
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
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError
from cordon_scanner.decide.decision.records import DecisionError, Instants
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.points import PointRuntime

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
    from cordon_scanner.decide.decision.outcome import Decision

REQUIRED_BUNDLE: Final = "policy_bundle"
"""What `decide()` is told is missing while no bundle is held."""


class LocalRuntime:
    """Decides at one execution point from the policy bundle it holds."""

    def __init__(
        self, *, root_public: bytes, delegation: object, tenant: str, baseline: CompiledPolicy
    ) -> None:
        baseline.verify()
        self._root, self._delegation, self._tenant = root_public, delegation, tenant
        self._baseline = baseline
        self._held: dict[str, Any] | None = None
        self._policy: CompiledPolicy | None = None

    @property
    def held(self) -> dict[str, Any] | None:
        """The payload of the bundle held (verified when it was taken), or None."""
        return self._held

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
        return state

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
        return PointRuntime.ask(
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

    @staticmethod
    def _policy_of(bundle: dict[str, Any]) -> CompiledPolicy:
        """The compiled policy a bundle carries, checked: sealed, and not outliving the bundle."""
        document = bundle.get("policy")
        if not isinstance(document, dict):
            raise BundleError("the bundle carries no compiled policy")
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
