"""`policy pull` keeps a bundle that verifies offline against the tenant root and refuses one that does not, keeping what it held."""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from cordon_scanner.cli.commands.policy import PolicyCommand
from cordon_scanner.cloud.agent.decision_delegation import DecisionDelegation
from cordon_scanner.cloud.bundle_chain import Dsse
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, TENANT, Kit, Platform


class Site:
    """The store as the command sees it: one fixed answer."""

    def __init__(
        self, bundles: list[dict[str, Any]], delegations: list[dict[str, Any]] | None = None
    ) -> None:
        data: dict[str, Any] = {"restart": False, "bundles": bundles}
        if delegations is not None:
            data["delegations"] = delegations
        self.body = json.dumps({"status": True, "message": "ok", "data": data}).encode()

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        return 200, {"ETag": '"one"'}, self.body


class Pull:
    @staticmethod
    def run(
        tmp_path: Path, platform: Platform, site: Site, minutes: int = 60, replace: bool = False
    ) -> int:
        delegation = tmp_path / "delegation.json"
        delegation.write_text(json.dumps(platform.delegation()), encoding="utf-8")
        args = argparse.Namespace(
            policy_command="pull",
            url="https://store.example.invalid/bundles",
            root=platform.root.public.hex(),
            delegation=str(delegation),
            tenant=TENANT,
            store=str(tmp_path / "store"),
            replace_root=replace,
        )
        return PolicyCommand.run(args, fetch=site, now=T0 + timedelta(minutes=minutes))

    @staticmethod
    def bundle(platform: Platform, lifetime: timedelta) -> dict[str, Any]:
        expires = T0 + lifetime
        return platform.publish(Kit.compiled(1, expires), issued=T0, expires=expires)

    @staticmethod
    def kept(tmp_path: Path) -> list[object] | None:
        return LocalStore(tmp_path / "store").load_bundle()


class TestThePullCommand:
    def test_a_bundle_that_verifies_is_kept(self, tmp_path: Path, capsys) -> None:
        platform = Platform()
        site = Site([Pull.bundle(platform, timedelta(days=1))])
        assert Pull.run(tmp_path, platform, site) == 0
        assert "policy bundle: new" in capsys.readouterr().out and Pull.kept(tmp_path)

    def test_an_expired_bundle_is_refused_by_name_and_nothing_is_kept(
        self, tmp_path: Path, capsys
    ) -> None:
        platform = Platform()
        site = Site([Pull.bundle(platform, timedelta(minutes=30))])
        assert Pull.run(tmp_path, platform, site, minutes=60) != 0
        assert "bundle_expired" in capsys.readouterr().out and not Pull.kept(tmp_path)

    def test_a_bundle_signed_under_another_root_is_refused_and_the_held_one_stays(
        self, tmp_path: Path
    ) -> None:
        platform = Platform()
        assert Pull.run(tmp_path, platform, Site([Pull.bundle(platform, timedelta(days=1))])) == 0
        held = Pull.kept(tmp_path)
        stranger = Platform(root=Platform().policy_key)
        forged = Pull.bundle(stranger, timedelta(days=2))
        assert Pull.run(tmp_path, platform, Site([forged])) != 0
        assert Pull.kept(tmp_path) == held

    def test_a_store_that_does_not_answer_keeps_what_is_held(self, tmp_path: Path) -> None:
        platform = Platform()
        assert Pull.run(tmp_path, platform, Site([Pull.bundle(platform, timedelta(days=1))])) == 0
        held = Pull.kept(tmp_path)

        def down(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
            raise OSError("down")

        assert Pull.run(tmp_path, platform, down) != 0  # type: ignore[arg-type]
        assert Pull.kept(tmp_path) == held


class TestTheFirstRootIsKept:
    def test_a_different_root_is_refused_unless_it_is_replaced_on_purpose(
        self, tmp_path: Path, capsys
    ) -> None:
        first = Platform()
        assert Pull.run(tmp_path, first, Site([Pull.bundle(first, timedelta(days=1))])) == 0
        other = Platform(root=Platform().policy_key)
        site = Site([Pull.bundle(other, timedelta(days=1))])
        assert Pull.run(tmp_path, other, site) != 0
        assert "another root key" in capsys.readouterr().err
        assert Pull.run(tmp_path, other, site, replace=True) == 0


class TestTheDecisionDelegationIsKept:
    """BP-15-15: under a root the customer holds, the command keeps the decision delegation the store serves, once it verifies."""

    @staticmethod
    def delegation(platform: Platform, sequence: int) -> dict[str, Any]:
        decider = Ed25519Signer(Kit.seed("pull-decider"))
        return Platform.sign(
            "application/vnd.cordon.decision-delegation+json",
            {
                "_type": "cordon.decision-delegation/v1",
                "tenant": TENANT,
                "issued_at": T0.isoformat(),
                "sequence": sequence,
                "root_keyid": Dsse.keyid(platform.root.public),
                "root_issued_at": T0.isoformat(),
                "policy_keyid": Dsse.keyid(platform.policy_key.public),
                "keys": [
                    {
                        "role": "decision.cloud",
                        "version": 1,
                        "keyid": Dsse.keyid(decider.public),
                        "public": decider.public.hex(),
                        "not_before": (T0 - timedelta(hours=1)).isoformat(),
                        "valid_until": (T0 + timedelta(days=7)).isoformat(),
                    }
                ],
            },
            platform.policy_key,
        )

    def test_a_delegation_that_verifies_is_kept_beside_the_bundle(self, tmp_path: Path) -> None:
        platform = Platform()
        bundle = Pull.bundle(platform, timedelta(days=1))
        site = Site([bundle], [self.delegation(platform, 3)])
        assert Pull.run(tmp_path, platform, site) == 0
        kept = DecisionDelegation.stored(LocalStore(tmp_path / "store"))
        assert DecisionDelegation.sequence_of(kept) == 3

    def test_one_signed_by_another_key_does_not_stop_the_bundle_and_is_reported(
        self, tmp_path: Path, capsys
    ) -> None:
        platform = Platform()
        bundle = Pull.bundle(platform, timedelta(days=1))
        forged = self.delegation(Platform(policy_key=Ed25519Signer(Kit.seed("forger"))), 3)
        assert Pull.run(tmp_path, platform, Site([bundle], [forged])) == 0
        seen = capsys.readouterr()
        assert Pull.kept(tmp_path)  # the verified bundle is applied
        assert DecisionDelegation.stored(LocalStore(tmp_path / "store")) is None
        assert "decision delegation refused:" in seen.err
        assert "policy bundle: new; decision delegation refused:" in seen.out

    def test_the_delegation_held_stays_when_a_later_one_is_refused(self, tmp_path: Path) -> None:
        platform = Platform()
        good = Site([Pull.bundle(platform, timedelta(days=1))], [self.delegation(platform, 5)])
        assert Pull.run(tmp_path, platform, good) == 0
        older = Site([Pull.bundle(platform, timedelta(days=2))], [self.delegation(platform, 4)])
        assert Pull.run(tmp_path, platform, older) == 0
        kept = DecisionDelegation.stored(LocalStore(tmp_path / "store"))
        assert DecisionDelegation.sequence_of(kept) == 5
