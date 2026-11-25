"""BP-15-15, scanner half: under a root the customer holds, the root's delegation names only the policy key, the policy key signs a decision
delegation naming the decision keys, and a decision verifies through both links. The one-link path (a root that names a decision key) is unchanged."""

from __future__ import annotations

import copy
from datetime import timedelta
from typing import Any

import pytest
from test_decision_envelope import Fixture

from cordon_scanner.cloud.agent.decision_delegation import (
    DECISION_DELEGATION_SCHEMA,
    DECISION_DELEGATION_TYPE,
    DecisionDelegation,
)
from cordon_scanner.cloud.agent.decision_envelope import DecisionEnvelope
from cordon_scanner.cloud.bundle_chain import BundleError, Dsse
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, TENANT, Kit, Platform

DECIDER = Ed25519Signer(Kit.seed("two-link-decider"))
STRANGER = Ed25519Signer(Kit.seed("two-link-stranger"))
NOW = T0 + timedelta(hours=2)


class Chain:
    """A customer root, its delegation naming the policy key, and the policy key's decision delegation."""

    def __init__(self) -> None:
        self.platform = Platform()
        self.policy_until = T0 + timedelta(days=90)

    def root_delegation(
        self, *, with_decision_key: bool = False, issued_at: str | None = None
    ) -> dict[str, Any]:
        keys = [
            {
                "keyid": Dsse.keyid(self.platform.policy_key.public),
                "public": self.platform.policy_key.public.hex(),
                "role": "policy",
                "not_before": (T0 - timedelta(days=1)).isoformat(),
                "valid_until": self.policy_until.isoformat(),
                "version": 1,
            }
        ]
        if with_decision_key:
            keys.append(self.entry(DECIDER, role="decision.cloud"))
        document = {
            "_type": "cordon.delegation/v1",
            "tenant": TENANT,
            "issued_at": issued_at or T0.isoformat(),
            "keys": keys,
        }
        return Platform.sign("application/vnd.cordon.delegation+json", document, self.platform.root)

    @staticmethod
    def entry(
        signer: Ed25519Signer, *, role: str = "decision.cloud", **changes: Any
    ) -> dict[str, Any]:
        base = {
            "role": role,
            "version": 1,
            "keyid": Dsse.keyid(signer.public),
            "public": signer.public.hex(),
            "not_before": (T0 - timedelta(hours=1)).isoformat(),
            "valid_until": (T0 + timedelta(days=7)).isoformat(),
        }
        return {**base, **changes}

    def decision_delegation(
        self, *, signer: Ed25519Signer | None = None, sequence: int = 4, **changes: Any
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "_type": DECISION_DELEGATION_SCHEMA,
            "tenant": TENANT,
            "issued_at": T0.isoformat(),
            "sequence": sequence,
            "root_keyid": Dsse.keyid(self.platform.root.public),
            "root_issued_at": T0.isoformat(),
            "policy_keyid": Dsse.keyid(self.platform.policy_key.public),
            "keys": [self.entry(DECIDER)],
            **changes,
        }
        return Platform.sign(DECISION_DELEGATION_TYPE, document, signer or self.platform.policy_key)

    def verify(
        self,
        decision_delegation: object,
        *,
        root: dict[str, Any] | None = None,
        by: Ed25519Signer = DECIDER,
        at=NOW,
        min_sequence: int = 0,
    ) -> dict[str, Any]:
        envelope = Fixture.sign(Fixture.decision(), by)
        return DecisionEnvelope.verify(
            envelope,
            root_public=self.platform.root.public,
            delegation=root or self.root_delegation(),
            tenant=TENANT,
            now=at,
            decision_delegation=decision_delegation,
            min_sequence=min_sequence,
        )


class ChainTests:
    @pytest.fixture
    def chain(self) -> Chain:
        return Chain()


class TestAValidChain(ChainTests):
    def test_a_decision_signed_by_the_key_the_policy_key_delegated_verifies(
        self, chain: Chain
    ) -> None:
        assert chain.verify(chain.decision_delegation())["predicate"]["state"]

    def test_an_equal_sequence_is_the_same_document_and_is_accepted(self, chain: Chain) -> None:
        assert chain.verify(chain.decision_delegation(sequence=4), min_sequence=4)

    def test_a_higher_sequence_is_accepted(self, chain: Chain) -> None:
        assert chain.verify(chain.decision_delegation(sequence=9), min_sequence=4)


class TestWhatIsRefused(ChainTests):
    def test_a_decision_key_the_policy_key_did_not_delegate(self, chain: Chain) -> None:
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(), by=STRANGER)

    def test_a_decision_delegation_signed_by_another_key_than_the_policy_key(
        self, chain: Chain
    ) -> None:
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(signer=STRANGER))

    def test_a_decision_delegation_naming_a_policy_key_the_root_did_not_delegate(
        self, chain: Chain
    ) -> None:
        with pytest.raises(BundleError):
            chain.verify(
                chain.decision_delegation(signer=STRANGER, policy_keyid=Dsse.keyid(STRANGER.public))
            )

    def test_a_lower_sequence_replayed(self, chain: Chain) -> None:
        with pytest.raises(BundleError, match="older"):
            chain.verify(chain.decision_delegation(sequence=3), min_sequence=4)

    @pytest.mark.parametrize("sequence", ["4", 4.0, True, None, -1])
    def test_a_sequence_that_is_not_a_whole_number(self, chain: Chain, sequence: Any) -> None:
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(sequence=sequence))

    def test_a_key_delegated_past_the_policy_keys_own_window(self, chain: Chain) -> None:
        late = chain.entry(
            DECIDER, valid_until=(chain.policy_until + timedelta(days=1)).isoformat()
        )
        with pytest.raises(BundleError, match="past the policy key"):
            chain.verify(chain.decision_delegation(keys=[late]))

    def test_a_key_with_no_end(self, chain: Chain) -> None:
        open_ended = chain.entry(DECIDER)
        del open_ended["valid_until"]
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(keys=[open_ended]))

    def test_a_key_that_ends_before_it_starts(self, chain: Chain) -> None:
        backwards = chain.entry(
            DECIDER, not_before=T0.isoformat(), valid_until=(T0 - timedelta(days=1)).isoformat()
        )
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(keys=[backwards]))

    def test_a_key_used_after_its_own_window(self, chain: Chain) -> None:
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(), at=T0 + timedelta(days=7, minutes=1))

    def test_a_key_used_before_its_own_window(self, chain: Chain) -> None:
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(), at=T0 - timedelta(hours=2))

    @pytest.mark.parametrize("field", ["not_before", "valid_until"])
    def test_a_time_with_no_zone(self, chain: Chain, field: str) -> None:
        naive = chain.entry(DECIDER, **{field: "2026-11-25T09:00:00"})
        with pytest.raises(BundleError, match="zone"):
            chain.verify(chain.decision_delegation(keys=[naive]))

    def test_a_key_id_that_is_not_the_hash_of_its_key(self, chain: Chain) -> None:
        forged = chain.entry(DECIDER, keyid="ab" * 32)
        with pytest.raises(BundleError, match="id is not"):
            chain.verify(chain.decision_delegation(keys=[forged]))

    @pytest.mark.parametrize("public", ["", "xyz", "ab" * 31, "AB" * 32])
    def test_a_public_key_that_is_not_32_bytes_of_hex(self, chain: Chain, public: str) -> None:
        with pytest.raises(BundleError):
            chain.verify(chain.decision_delegation(keys=[chain.entry(DECIDER, public=public)]))

    def test_a_key_that_is_not_a_decision_role(self, chain: Chain) -> None:
        with pytest.raises(BundleError, match="not a decision key"):
            chain.verify(chain.decision_delegation(keys=[chain.entry(DECIDER, role="policy")]))

    def test_a_decision_delegation_for_another_tenant(self, chain: Chain) -> None:
        with pytest.raises(BundleError, match="tenant"):
            chain.verify(chain.decision_delegation(tenant="another"))

    def test_one_bound_to_another_root(self, chain: Chain) -> None:
        with pytest.raises(BundleError, match="this root"):
            chain.verify(chain.decision_delegation(root_keyid="cd" * 32))

    @pytest.mark.parametrize("bound", ["2026-01-01T00:00:00+00:00", None, 5])
    def test_one_bound_to_another_root_delegation(self, chain: Chain, bound: Any) -> None:
        with pytest.raises(BundleError, match="root delegation"):
            chain.verify(chain.decision_delegation(root_issued_at=bound))

    def test_one_issued_when_the_policy_key_was_not_valid(self, chain: Chain) -> None:
        with pytest.raises(BundleError, match="not valid when"):
            chain.verify(
                chain.decision_delegation(
                    issued_at=(chain.policy_until + timedelta(days=1)).isoformat()
                )
            )

    def test_no_decision_delegation_at_all(self, chain: Chain) -> None:
        with pytest.raises(BundleError):
            chain.verify(None)

    def test_a_decision_delegation_with_an_edited_payload(self, chain: Chain) -> None:
        envelope = copy.deepcopy(chain.decision_delegation())
        envelope["payload"] = envelope["payload"][:-4] + "AAAA"
        with pytest.raises(BundleError):
            chain.verify(envelope)


class TestTheOneLinkPathIsUnchanged(ChainTests):
    def test_a_root_that_names_a_decision_key_verifies_without_the_decision_delegation(
        self, chain: Chain
    ) -> None:
        assert chain.verify(None, root=chain.root_delegation(with_decision_key=True))

    def test_and_does_not_read_a_decision_delegation_it_is_given(self, chain: Chain) -> None:
        garbage = {"payloadType": DECISION_DELEGATION_TYPE, "payload": "!!", "signatures": []}
        assert chain.verify(garbage, root=chain.root_delegation(with_decision_key=True))

    def test_root_names_decision_says_which_path(self, chain: Chain) -> None:
        root = chain.platform.root.public
        assert not DecisionDelegation.root_names_decision(root, chain.root_delegation(), TENANT)
        assert DecisionDelegation.root_names_decision(
            root, chain.root_delegation(with_decision_key=True), TENANT
        )
