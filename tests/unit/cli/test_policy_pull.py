"""`policy pull` keeps a bundle that verifies offline against the tenant root and refuses one that does not, keeping what it held."""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from cordon_scanner.cli.commands.policy import PolicyCommand
from cordon_scanner.cloud.local_store import LocalStore
from kits.bundle_kit import T0, TENANT, Kit, Platform


class Site:
    """The store as the command sees it: one fixed answer."""

    def __init__(self, bundles: list[dict[str, Any]]) -> None:
        self.body = json.dumps(
            {"status": True, "message": "ok", "data": {"restart": False, "bundles": bundles}}
        ).encode()

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        return 200, {"ETag": '"one"'}, self.body


class Pull:
    @staticmethod
    def run(tmp_path: Path, platform: Platform, site: Site, minutes: int = 60) -> int:
        delegation = tmp_path / "delegation.json"
        delegation.write_text(json.dumps(platform.delegation()), encoding="utf-8")
        args = argparse.Namespace(
            policy_command="pull",
            url="https://store.example.invalid/bundles",
            root=platform.root.public.hex(),
            delegation=str(delegation),
            tenant=TENANT,
            store=str(tmp_path / "store"),
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
