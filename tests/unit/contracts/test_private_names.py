"""`PrivateNames`: a private package leaves the tenant only as a keyed hash (spec 22.2 Q1)."""

from __future__ import annotations

import pytest

from cordon_scanner.contracts.private_names import PrivateNames
from kits.tenant_keys import ShortKeys, StaticTenantKeys

KEYS = StaticTenantKeys()
PLAIN = "pkg:npm/%40acme/billing"


class TestWhatIsPrivate:
    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({}, False),
            ({"registry": "registry.npmjs.org"}, False),
            ({"registry": "PyPI.org/"}, False),
            ({"registry": "npm.corp.example.com"}, True),
            ({"published": False}, True),
            ({"published": True, "registry": "registry.npmjs.org"}, False),
            ({"namespace": "@Acme", "internal_namespaces": ["@acme"]}, True),
            ({"namespace": "@other", "internal_namespaces": ["@acme"]}, False),
        ],
    )
    def test_a_name_is_private_by_registry_namespace_or_publication(self, kwargs, expected) -> None:
        assert PrivateNames.is_private(**kwargs) is expected


class TestTheHashedForm:
    def test_it_keeps_the_kind_prefix_and_hides_the_name(self) -> None:
        hashed = PrivateNames.hashed(PLAIN, "tenant-a", KEYS)
        assert hashed.startswith("hash:pkg/") and len(hashed) == len("hash:pkg/") + 64
        assert "acme" not in hashed and "billing" not in hashed

    def test_it_is_stable_and_differs_by_tenant_and_name(self) -> None:
        a = PrivateNames.hashed(PLAIN, "tenant-a", KEYS)
        assert a == PrivateNames.hashed(PLAIN, "tenant-a", KEYS)
        assert a != PrivateNames.hashed(PLAIN, "tenant-b", KEYS)
        assert a != PrivateNames.hashed("pkg:npm/%40acme/payments", "tenant-a", KEYS)

    def test_other_kinds_keep_their_own_prefix(self) -> None:
        assert PrivateNames.hashed("skill:local/.claude/skills/x", "t", KEYS).startswith(
            "hash:skill/"
        )

    def test_a_short_key_or_a_non_id_is_refused(self) -> None:
        with pytest.raises(ValueError):
            PrivateNames.hashed(PLAIN, "t", ShortKeys())
        with pytest.raises(ValueError):
            PrivateNames.hashed("not an id", "t", KEYS)

    def test_a_hash_is_not_hashed_again(self) -> None:
        with pytest.raises(ValueError):
            PrivateNames.hashed(PrivateNames.hashed(PLAIN, "t", KEYS), "t", KEYS)


class TestWhatLeavesTheTenant:
    def test_a_public_name_stays_plain(self) -> None:
        assert (
            PrivateNames.outbound("pkg:npm/left-pad", "t", KEYS, private=False)
            == "pkg:npm/left-pad"
        )

    def test_a_private_name_leaves_hashed_by_default(self) -> None:
        sent = PrivateNames.outbound(PLAIN, "t", KEYS, private=True)
        assert PrivateNames.is_hashed(sent) and sent == PrivateNames.hashed(PLAIN, "t", KEYS)

    def test_a_tenant_can_opt_in_to_plain_private_names(self) -> None:
        assert PrivateNames.outbound(PLAIN, "t", KEYS, private=True, plain_opt_in=True) == PLAIN
