"""The execution plane's local decision runtime: every point keeps deciding with the control plane down.

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

With a `LocalStore` the runtime also keeps what it needs to start offline: `accept` keeps the bundle taken and `resume` takes
it again after a restart (verified again, expired or not: an expired bundle still decides, as `R202`); a decision is looked up by its
`inputs_digest` before it is made and kept after (equal inputs are equal decisions, so nothing kept is stale); each decision made
is queued for upload and `drain` sends the queue oldest first when the control plane is back; the age of the stored intel
snapshot is the `intel_age_s` of the question unless the caller gives one.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Final, NamedTuple

from cordon_scanner.cloud.agent.decision_envelope import DecisionEnvelope
from cordon_scanner.cloud.agent.feed_serials import KIND as FEED_KIND
from cordon_scanner.cloud.agent.feed_serials import FeedSerials
from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, BundleRefused
from cordon_scanner.cloud.bundle_loosening import Granted, Loosening
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.private_names import PrivateNames
from cordon_scanner.decide.decision.outcome import Decision, Relaxation
from cordon_scanner.decide.decision.records import DecisionError, Instants
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.rules.feed_gaps import FeedGaps

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.cloud.local_store import Drained, LocalStore, Pending
    from cordon_scanner.contracts.private_names import TenantKeys
    from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
    from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer

REQUIRED_BUNDLE: Final = "policy_bundle"
"""What `decide()` is told is missing while no bundle is held."""


class Answer(NamedTuple):
    """A decision and where it came from: `decided` now, `kept` (the same inputs were decided before), or `remembered` (an earlier
    ALLOW served because the facts that would refresh it could not be had: see `LocalRuntime.REMEMBERED_FOR`)."""

    decision: Decision
    source: str


@dataclass(frozen=True, slots=True)
class NamePolicy:
    """How a name leaves the tenant (spec 22.2 Q1): private names as the keyed hash, public ones plain, unless the tenant opted in."""

    tenant: str
    keys: TenantKeys
    plain_opt_in: bool = False
    internal_namespaces: tuple[str, ...] = ()


class LocalRuntime:
    """Decides at one execution point from the policy bundle it holds."""

    #: The shortfalls an earlier ALLOW may stand in for: required evidence that could not be fetched (R200, a registry that is
    #: down) and intelligence older than the policy allows (R201). Never an expired bundle (R202), an analysis that did not
    #: finish (R204) or anything about the content or the digest.
    REMEMBERED_FOR: ClassVar[frozenset[str]] = frozenset({"R200", "R201"})

    def __init__(
        self,
        *,
        root_public: bytes,
        delegation: object,
        tenant: str,
        baseline: CompiledPolicy,
        store: LocalStore | None = None,
        names: NamePolicy | None = None,
        signer: Ed25519Signer | None = None,
    ) -> None:
        baseline.verify()
        self._store = store
        self._signer = signer
        self._names = names
        self._root, self._delegation, self._tenant = root_public, delegation, tenant
        self._baseline = baseline
        self._held: dict[str, Any] | None = None
        self._policy: CompiledPolicy | None = None
        self._loosenings: tuple[Granted, ...] = ()

    @property
    def loosening_log(self) -> tuple[str, ...]:
        """The ids of the platform's decision-log entries of the loosenings that let the held policy through, for an auditor (not checked online)."""
        return tuple(grant.log_id for grant in self._loosenings)

    def _loosened(
        self, held: dict[str, Any] | None, offered: list[dict[str, Any]], now: datetime
    ) -> tuple[Granted, ...]:
        """Each bundle compared with the one before it (the held one first): the loosenings that covered them, or `BundleRefused`."""
        if held is None:
            return ()
        keys = BundleChain.policy_keys(self._root, self._delegation, self._tenant, now)
        used: list[Granted] = []
        for bundle in offered:
            used += Loosening.check(held, bundle, policy_keys=keys, tenant=self._tenant, now=now)
            held = bundle
        return tuple(used)

    @property
    def held(self) -> dict[str, Any] | None:
        """The payload of the bundle held (verified when it was taken), or None."""
        return self._held

    @property
    def policy(self) -> CompiledPolicy:
        """The compiled policy decisions are made under now: the held bundle's, or the baseline while none is held."""
        return self._policy if self._policy is not None else self._baseline

    @property
    def lists(self) -> dict[str, Any]:
        """The lists the held bundle carries beside its compiled policy (`lists`), or none."""
        found = (self._held or {}).get("lists")
        return dict(found) if isinstance(found, dict) else {}

    def kept_scan(self, key: str) -> dict[str, Any] | None:
        """The evidence a scan produced earlier for `key` (a digest and a rules version), or None."""
        return self._store.recall_scan(key) if self._store is not None else None

    def keep_scan(self, key: str, evidence: dict[str, Any]) -> None:
        if self._store is not None:
            self._store.keep_scan(key, evidence)

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
            documents = [BundleChain.unverified_payload_document(e) for e in envelopes]
            self._loosenings = self._loosened(self._held, documents, now) or self._loosenings
            self._policy = self._policy_of(bundle)
            self._held = bundle
            if self._store is not None:
                self._store.save_bundle([list(envelopes)[-1]])
            self.note_feed(now)
        return state

    def restart(self, envelope: object, now: datetime) -> str:
        """A fresh start the bundle store asks for (its answer says `restart`: it no longer holds the bundles between): the
        newest bundle alone, verified like any other and never older than the one held. The chain between is not checked, because
        the store says it cannot offer it; everything else is: the signature, the tenant, the expiry, the policy, and that it is
        the same scope and not a rollback or a fork."""
        _, bundle = BundleChain.accept_bundle(
            root_public=self._root,
            delegation=self._delegation,
            envelope=envelope,
            tenant=self._tenant,
            now=now,
            held=None,
        )
        held = self._held
        if held is not None:
            if bundle["scope"] != held["scope"]:
                raise BundleRefused(
                    BundleRefused.CHAIN_BROKEN, "this bundle is for another scope than the one held"
                )
            have, got = int(held["version"]), int(bundle["version"])
            if got < have:
                raise BundleRefused(
                    BundleRefused.ROLLED_BACK,
                    f"version {got} is older than the version {have} held",
                )
            if got == have:
                if BundleChain.payload_sha(bundle) == BundleChain.payload_sha(held):
                    return "unchanged"
                raise BundleRefused(
                    BundleRefused.FORKED,
                    f"version {got} is not the version {have} held: another payload",
                )
        self._loosenings = self._loosened(held, [bundle], now) or self._loosenings
        self._policy = self._policy_of(bundle)
        self._held = bundle
        if self._store is not None:
            self._store.save_bundle([envelope])
        return "new"

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
        self.note_feed(now)
        return True

    def collection_reason(self, now: datetime) -> str | None:
        """Why the agent's collection is degraded at `now`, from `CollectionStatus.REASONS`, or None when it is complete: no policy key valid (`key_expired`), no bundle held (`policy_unavailable`), or the held bundle past its expiry (`bundle_expired`)."""
        try:
            keys = BundleChain.policy_keys(self._root, self._delegation, self._tenant, now)
        except BundleError:
            return "policy_unavailable"
        if not keys:
            return "key_expired"
        if self._held is None:
            return "policy_unavailable"
        if Instants.parse(str(self._held["expires_at"])) < Instants.parse(now.isoformat()):
            return "bundle_expired"
        return None

    def note_feed(self, clock: datetime) -> bool:
        """Queue the feed serial pair the scans here run on, once per pair (`FeedSerials.queue`); False with no store or nothing new.

        Called when a session starts (a bundle accepted or resumed), so the sighting is queued ahead of the session's decisions."""
        if self._store is None:
            return False
        return FeedSerials.queue(self._store, FeedGaps.feed(), clock)

    def drain(
        self, send: Callable[[Pending], None], feed_send: Callable[[Pending], None] | None = None
    ) -> Drained:
        """Send the uploads queued while offline, oldest first, stopping at the first that fails (see `LocalStore.drain`). The outbox holds decisions and feed-serial sightings; sightings go to `feed_send` when given (`FeedSerials.send` for the device endpoint), else to `send` with the rest."""
        if self._store is None:
            raise BundleError("no local store: nothing is queued")
        if feed_send is None:
            return self._store.drain(send)
        return self._store.drain(lambda item: (feed_send if item.kind == FEED_KIND else send)(item))

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
        return self.answer(
            point,
            artifact,
            evidence,
            clock,
            environment=environment,
            scope_path=scope_path,
            actor=actor,
            relation=relation,
            online=online,
            intel_age_s=intel_age_s,
        ).decision

    def answer(
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
    ) -> Answer:
        """`ask`, with where the decision came from."""
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
        arguments: dict[str, Any] = {
            "environment": environment,
            "scope_path": scope_path,
            "actor": actor,
            "relation": relation,
            "online": online,
            "bundle_age_s": bundle_age,
            "intel_age_s": intel_age_s,
        }
        store = self._store
        key = (
            PointRuntime.key(point, artifact, asked, policy, clock, **arguments)
            if store is not None
            else None
        )
        if store is not None and key is not None:
            kept = store.cache_get(key)
            if kept is not None:
                return Answer(Decision.from_json(kept), "kept")
        decision = PointRuntime.ask(point, artifact, asked, policy, clock, **arguments)
        if store is None or key is None:
            return Answer(decision, "decided")
        stands_in = self._remembered(artifact, policy, arguments, decision, clock)
        if stands_in is not None:
            return Answer(stands_in, "remembered")
        store.cache_put(key, decision.to_json())
        store.enqueue("decision", self._upload(decision, artifact))
        self._remember(artifact, policy, arguments, decision, clock)
        return Answer(decision, "decided")

    # -- what an earlier ALLOW may stand in for ---------------------------------------------------

    @staticmethod
    def _about(
        artifact: ArtifactRef, policy: CompiledPolicy, arguments: dict[str, Any]
    ) -> str | None:
        """What an earlier ALLOW is kept under: this digest, under this policy, in this environment, scope and relation. Not the
        moment, the point or the ages: those are what change while the facts cannot be refreshed."""
        if artifact.digest is None:
            return None
        return ArtifactDigests.of_bytes(
            ArtifactDigests.canonical_json(
                {
                    "digest": artifact.digest,
                    "policy": policy.sha256,
                    "environment": arguments["environment"],
                    "scope": list(arguments["scope_path"]),
                    "relation": arguments["relation"],
                }
            )
        )

    def _remember(
        self,
        artifact: ArtifactRef,
        policy: CompiledPolicy,
        arguments: dict[str, Any],
        decision: Decision,
        clock: datetime,
    ) -> None:
        """Keep a decision that allowed with every fact in hand (no R2xx shortfall, not even a warning)."""
        about = self._about(artifact, policy, arguments)
        if (
            self._store is None
            or about is None
            or decision.state not in ("ALLOW", "ALLOW_WITH_CONDITIONS")
            or any(code.startswith("R2") for code in decision.reason_codes)
        ):
            return
        self._store.remember_allow(about, decision.to_json(), Instants.text(clock))

    def _remembered(
        self,
        artifact: ArtifactRef,
        policy: CompiledPolicy,
        arguments: dict[str, Any],
        decision: Decision,
        clock: datetime,
    ) -> Decision | None:
        """The earlier ALLOW for this digest, when this decision is a block or review only for want of facts that could not be
        had (`REMEMBERED_FOR`, and nothing else), the policy is the same one, and the ALLOW is no older than the policy's `defaults.degrade.serve_last_allow_hours` (24 unless it says otherwise; 0 turns it off). The decision
        served carries a `serve_last_allow` relaxation for each shortfall it stood in for."""
        codes = {
            code for code in decision.reason_codes if not code.startswith("R9")
        }  # R9xx say why something allows
        about = self._about(artifact, policy, arguments)
        if (
            self._store is None
            or about is None
            or decision.state in ("ALLOW", "ALLOW_WITH_CONDITIONS")
            or not codes
            or not codes <= self.REMEMBERED_FOR
        ):
            return None
        window = policy.defaults.serve_last_allow_seconds()
        recalled = self._store.recall_allow(about) if window > 0 else None
        if recalled is None:
            return None
        earlier, made_at = recalled
        if not 0 <= (clock - Instants.parse(made_at)).total_seconds() <= window:
            return None
        served = Decision.from_json(earlier)
        relaxed = {
            Relaxation(code, "serve_last_allow", "allow", str(arguments["environment"]))
            for code in codes
        }
        return replace(
            served,
            relaxations=tuple(
                sorted({*(served.relaxations or ()), *relaxed}, key=Relaxation.sort_key)
            ),
        )

    def _upload(self, decision: Decision, artifact: ArtifactRef) -> bytes:
        """What a decision made here sends the control plane: the decision, the digest and version, and the subject in the form
        that may leave (a private name only as its keyed hash; with no key to hash it by, the name is withheld)."""
        names = self._names
        private = PrivateNames.is_private(
            registry=artifact.registry,
            namespace=artifact.namespace,
            internal_namespaces=names.internal_namespaces if names else (),
        )
        subject: str | None
        if names is not None:
            subject = PrivateNames.outbound(
                artifact.subject_id,
                names.tenant,
                names.keys,
                private=private,
                plain_opt_in=names.plain_opt_in,
            )
        else:
            subject = None if private else artifact.subject_id
        document: dict[str, Any] = {
            "schema": "cordon.upload.decision/v1",
            "subject": subject,
            "digest": artifact.digest,
            "version": artifact.version,
            "decision": decision.to_json(),
            "feed": FeedGaps.feed(),
        }
        if self._signer is not None and artifact.digest is not None:
            document["signed"] = DecisionEnvelope.sign(
                decision, self._signer, subject_id=artifact.subject_id, digest=artifact.digest
            )
        return ArtifactDigests.canonical_json(document)

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


__all__ = ["REQUIRED_BUNDLE", "Answer", "LocalRuntime", "NamePolicy"]
