"""The client half of the policy bundle chain agrees with the platform on every fixture case.

`bundle_chain_fixtures.json` was produced by the platform (the thirteen cases of its bundle-chain contract: raw signed
envelopes, the held envelope, the clock and the expected outcome). The client must take what the platform's
`TrustChain.accept_bundle` and `accept_chain` take, refuse what they refuse, and name each refusal the same way.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

import pytest

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, BundleRefused, Dsse
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits import bundle_kit
from support import ROOT as REPO

FIXTURES = json.loads(
    (REPO / "tests" / "unit" / "cloud" / "bundle_chain_fixtures.json").read_text(encoding="utf-8")
)
ROOT_KEY = bytes.fromhex(FIXTURES["root_public"])
DELEGATION = FIXTURES["delegation"]
TENANT = FIXTURES["tenant"]
CASES = FIXTURES["cases"]


class Kit:
    @staticmethod
    def run(case: dict[str, Any], *, chain: bool | None = None) -> tuple[str, dict[str, Any]]:
        held_envelope = case["held_envelope"]
        held = BundleChain.unverified_payload_document(held_envelope) if held_envelope else None
        now = datetime.fromisoformat(case["now"])
        offered = case["offered"]
        if chain is None:
            chain = len(offered) > 1
        if chain:
            return BundleChain.accept_chain(
                root_public=ROOT_KEY,
                delegation=DELEGATION,
                envelopes=offered,
                tenant=TENANT,
                now=now,
                held=held,
            )
        return BundleChain.accept_bundle(
            root_public=ROOT_KEY,
            delegation=DELEGATION,
            envelope=offered[0],
            tenant=TENANT,
            now=now,
            held=held,
        )


class TestTheThirteenFixtureCases:
    def test_there_are_thirteen_and_each_outcome_is_named(self) -> None:
        assert len(CASES) == 13
        assert {next(iter(case["expect"])) for case in CASES} == {
            "state",
            "refused",
            "verification_failed",
        }

    @pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
    def test_the_client_agrees_with_the_platform(self, case: dict[str, Any]) -> None:
        expect = case["expect"]
        if "state" in expect:
            state, bundle = Kit.run(case)
            assert state == expect["state"]
            assert isinstance(bundle["version"], int)
        elif "refused" in expect:
            with pytest.raises(BundleRefused) as caught:
                Kit.run(case)
            assert caught.value.name == expect["refused"]
        else:
            with pytest.raises(BundleError) as caught:
                Kit.run(case)
            assert not isinstance(caught.value, BundleRefused), (
                "a bad signature is not a chain refusal"
            )

    @pytest.mark.parametrize(
        "case", [c for c in CASES if len(c["offered"]) == 1], ids=lambda c: c["name"]
    )
    def test_one_bundle_offered_as_a_chain_is_judged_the_same(self, case: dict[str, Any]) -> None:
        try:
            alone = Kit.run(case, chain=False)
        except BundleRefused as refused:
            with pytest.raises(BundleRefused) as caught:
                Kit.run(case, chain=True)
            assert caught.value.name == refused.name
        except BundleError:
            with pytest.raises(BundleError):
                Kit.run(case, chain=True)
        else:
            assert Kit.run(case, chain=True) == alone


class TestTheRefusalNames:
    def test_they_are_exactly_these_five(self) -> None:
        assert BundleRefused.NAMES == (
            "bundle_rolled_back",
            "bundle_forked",
            "bundle_chain_broken",
            "bundle_gap",
            "bundle_expired",
        )

    def test_every_name_the_fixtures_expect_is_one_of_them(self) -> None:
        wanted = {case["expect"]["refused"] for case in CASES if "refused" in case["expect"]}
        assert wanted <= set(BundleRefused.NAMES)

    def test_an_empty_catch_up_is_a_gap(self) -> None:
        with pytest.raises(BundleRefused) as caught:
            BundleChain.accept_chain(
                root_public=ROOT_KEY,
                delegation=DELEGATION,
                envelopes=[],
                tenant=TENANT,
                now=datetime.fromisoformat(CASES[0]["now"]),
            )
        assert caught.value.name == BundleRefused.GAP


class TestWhatIsSigned:
    def test_the_payload_sha_is_of_the_canonical_bytes_with_a_prefix(self) -> None:
        document = BundleChain.unverified_payload_document(CASES[2]["held_envelope"])
        sha = BundleChain.payload_sha(document)
        assert sha.startswith("sha256:") and len(sha) == len("sha256:") + 64
        reordered = dict(reversed(list(document.items())))
        assert BundleChain.payload_sha(reordered) == sha

    def test_the_successor_names_the_sha_of_the_held_payload(self) -> None:
        case = CASES[1]
        held = BundleChain.unverified_payload_document(case["held_envelope"])
        successor = BundleChain.unverified_payload_document(case["offered"][0])
        assert successor["version"] == held["version"] + 1
        assert successor["prev_sha"] == BundleChain.payload_sha(held)

    def test_the_first_bundle_is_version_one_with_an_empty_prev_sha(self) -> None:
        first = BundleChain.unverified_payload_document(CASES[0]["offered"][0])
        assert first["version"] == 1
        assert not first.get("prev_sha")


class TestWhatIsNotTrusted:
    def test_a_changed_signature_is_refused_as_untrusted_not_as_a_chain_break(self) -> None:
        case = copy.deepcopy(CASES[0])
        signature = bytearray(base64.b64decode(case["offered"][0]["signatures"][0]["sig"]))
        signature[0] ^= 0xFF
        case["offered"][0]["signatures"][0]["sig"] = base64.b64encode(bytes(signature)).decode(
            "ascii"
        )
        with pytest.raises(BundleError) as caught:
            Kit.run(case)
        assert not isinstance(caught.value, BundleRefused)

    def test_a_changed_payload_does_not_verify(self) -> None:
        case = copy.deepcopy(CASES[0])
        document = BundleChain.unverified_payload_document(case["offered"][0])
        document["version"] = 7
        case["offered"][0]["payload"] = base64.b64encode(BundleChain.canonical(document)).decode(
            "ascii"
        )
        with pytest.raises(BundleError) as caught:
            Kit.run(case)
        assert not isinstance(caught.value, BundleRefused)

    def test_another_pinned_root_trusts_no_delegation(self) -> None:
        case = CASES[0]
        with pytest.raises(BundleError):
            BundleChain.accept_bundle(
                root_public=bytes(32),
                delegation=DELEGATION,
                envelope=case["offered"][0],
                tenant=TENANT,
                now=datetime.fromisoformat(case["now"]),
            )

    def test_another_tenants_delegation_is_refused(self) -> None:
        case = CASES[0]
        with pytest.raises(BundleError):
            BundleChain.accept_bundle(
                root_public=ROOT_KEY,
                delegation=DELEGATION,
                envelope=case["offered"][0],
                tenant="another-tenant",
                now=datetime.fromisoformat(case["now"]),
            )

    @pytest.mark.parametrize(
        "envelope", [None, "text", [], {}, {"payloadType": "x"}, {"payload": 3}]
    )
    def test_a_malformed_envelope_is_an_error_not_a_crash(self, envelope: object) -> None:
        with pytest.raises(BundleError):
            BundleChain.accept_bundle(
                root_public=ROOT_KEY,
                delegation=DELEGATION,
                envelope=envelope,
                tenant=TENANT,
                now=datetime.fromisoformat(CASES[0]["now"]),
            )

    def test_a_clock_before_the_key_window_is_refused_and_a_few_minutes_early_is_not(self) -> None:
        delegation = BundleChain.delegation(ROOT_KEY, DELEGATION, tenant=TENANT)
        policy = next(
            key for key in delegation["keys"] if key["role"] == "policy" and "valid_until" in key
        )
        start = datetime.fromisoformat(policy["not_before"])
        assert BundleChain._valid_at(policy, start - timedelta(minutes=4))
        assert not BundleChain._valid_at(policy, start - timedelta(minutes=6))


class TestWhatTheEnvelopeCarries:
    def test_the_pre_authentication_encoding(self) -> None:
        assert Dsse.pae("t", b"abc") == b"DSSEv1 1 t 3 abc"

    def test_a_key_id_is_the_sha256_of_the_raw_key(self) -> None:
        assert len(Dsse.keyid(ROOT_KEY)) == 64
        assert Dsse.keyid(ROOT_KEY) == hashlib.sha256(ROOT_KEY).hexdigest()


class Tenant:
    """A tenant that brings its own root key."""

    @staticmethod
    def platform(label: str) -> bundle_kit.Platform:
        return bundle_kit.Platform(
            root=Ed25519Signer(bundle_kit.Kit.seed(label)),
            policy_key=Ed25519Signer(bundle_kit.Kit.seed(label + "-policy")),
        )

    @staticmethod
    def bundle(
        platform: bundle_kit.Platform, expires: timedelta = timedelta(days=30)
    ) -> dict[str, Any]:
        policy = bundle_kit.Kit.compiled(1, bundle_kit.T0 + expires)
        return platform.publish(policy, issued=bundle_kit.T0, expires=bundle_kit.T0 + expires)

    @staticmethod
    def offer(
        platform: bundle_kit.Platform, pinned: Ed25519Signer, envelope: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        return BundleChain.accept_bundle(
            root_public=pinned.public,
            delegation=platform.delegation(),
            envelope=envelope,
            tenant=bundle_kit.TENANT,
            now=bundle_kit.T0 + timedelta(hours=1),
        )


class TestABringYourOwnRoot:
    def test_a_bundle_under_the_tenants_own_root_verifies_offline(self) -> None:
        platform = Tenant.platform("byok-root")
        taken, bundle = Tenant.offer(platform, platform.root, Tenant.bundle(platform))
        assert taken == "new" and bundle["scope"] == bundle_kit.SCOPE

    def test_a_bundle_is_not_trusted_under_a_root_the_tenant_does_not_pin(self) -> None:
        old, new = Tenant.platform("byok-old"), Tenant.platform("byok-new")
        with pytest.raises(BundleError) as refused:
            Tenant.offer(old, new.root, Tenant.bundle(old))
        assert not isinstance(refused.value, BundleRefused)

    def test_a_bundle_past_its_expiry_is_refused_even_under_the_right_root(self) -> None:
        platform = Tenant.platform("byok-root")
        policy = bundle_kit.Kit.compiled(1, bundle_kit.T0 + timedelta(hours=1))
        envelope = platform.publish(
            policy, issued=bundle_kit.T0, expires=bundle_kit.T0 + timedelta(minutes=30)
        )
        with pytest.raises(BundleRefused) as refused:
            Tenant.offer(platform, platform.root, envelope)
        assert refused.value.name == BundleRefused.EXPIRED
