"""Row BP-6-12: a point pulls its bundle from the bundle store with an ETag and a version pin.

Each of the four points (the CLI, the hooks, the firewall, the gates) pulls a bundle, keeps it, and revalidates with the ETag; a bundle
held and not yet expired still decides when the store cannot be reached; a pin holds a point at a version.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from cordon_scanner.cloud.bundle_chain import BundleError, BundleRefused
from cordon_scanner.cloud.bundle_puller import BundlePuller
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.decide.decision.evidence import EvidenceSet
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, Kit, Platform, Things

POINTS = ("cli", "agent_hook", "firewall", "ci_gate")


class BundleStore:
    """The control plane's bundle store as the puller sees it: the bundles since a version, an ETag, and 304 when it matches."""

    def __init__(self, platform: Platform) -> None:
        self.platform = platform
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.down = False
        self.status = 200
        self.body: bytes | None = None
        self.generation = 0

    def etag(self) -> str:
        return f'"v{len(self.platform.chain)}.{self.generation}"'

    def fetch(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((url, dict(headers)))
        if self.down:
            raise ConnectionError("the bundle store is down")
        if self.status != 200:
            return self.status, {}, b""
        if headers.get("If-None-Match") == self.etag():
            return 304, {"ETag": self.etag()}, b""
        since = int(url.rsplit("since=", 1)[1])
        offered = [
            envelope
            for envelope, payload in zip(self.platform.chain, self.platform.payloads, strict=True)
            if payload["version"] > since
        ]
        return 200, {"ETag": self.etag()}, self.body or json.dumps({"bundles": offered}).encode()


class World:
    @staticmethod
    def point(tmp_path: Path, bundles: int = 1, pin: int | None = None):
        platform = Platform()
        for number in range(bundles):
            expires = T0 + timedelta(days=2)
            platform.publish(Kit.compiled(number + 1, expires), issued=T0, expires=expires)
        store = BundleStore(platform)
        local = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, local)
        return (
            platform,
            store,
            runtime,
            BundlePuller("https://bundles.example/v1/policy", store.fetch, local, pin=pin),
        )

    @staticmethod
    def publish(platform: Platform) -> None:
        expires = T0 + timedelta(days=2)
        platform.publish(Kit.compiled(len(platform.chain) + 1, expires), issued=T0, expires=expires)


class TestEachPointPullsKeepsAndRevalidates:
    @pytest.mark.parametrize("point", POINTS)
    def test_the_first_pull_takes_the_bundle_and_the_second_revalidates_with_the_etag(
        self, tmp_path: Path, point: str
    ) -> None:
        _platform, store, runtime, puller = World.point(tmp_path)
        assert puller.pull(runtime, T0) == "new" and runtime.held["version"] == 1  # type: ignore[index]
        assert "If-None-Match" not in store.calls[0][1]
        assert puller.pull(runtime, T0 + timedelta(minutes=5)) == "unchanged"
        assert store.calls[1][1]["If-None-Match"] == store.etag() and store.calls[1][0].endswith(
            "since=1"
        )
        decision = runtime.ask(
            point,
            Things.artifacts(1)[0],
            EvidenceSet(),
            T0 + timedelta(minutes=6),
            environment="production",
            scope_path=("acme",),
        )
        assert decision.state == "ALLOW" and decision.policy.version == 1

    @pytest.mark.parametrize("point", POINTS)
    def test_a_restarted_point_still_revalidates_with_the_etag_it_kept(
        self, tmp_path: Path, point: str
    ) -> None:
        platform, store, runtime, puller = World.point(tmp_path)
        puller.pull(runtime, T0)
        again = Kit.runtime(platform, LocalStore(tmp_path))
        assert again.resume(T0 + timedelta(minutes=1))
        BundlePuller("https://bundles.example/v1/policy", store.fetch, LocalStore(tmp_path)).pull(
            again, T0 + timedelta(minutes=2)
        )
        assert store.calls[-1][1]["If-None-Match"] == store.etag(), point

    def test_a_new_bundle_is_taken_and_catching_up_takes_every_bundle_in_order(
        self, tmp_path: Path
    ) -> None:
        platform, _store, runtime, puller = World.point(tmp_path, bundles=3)
        assert puller.pull(runtime, T0) == "new" and runtime.held["version"] == 3  # type: ignore[index]
        World.publish(platform)
        assert (
            puller.pull(runtime, T0 + timedelta(minutes=1)) == "new"
            and runtime.held["version"] == 4
        )  # type: ignore[index]


class TestAStaleCacheStillDecides:
    def test_with_the_store_down_a_held_bundle_that_has_not_expired_decides_as_before(
        self, tmp_path: Path
    ) -> None:
        _platform, store, runtime, puller = World.point(tmp_path)
        puller.pull(runtime, T0)
        store.down = True
        assert puller.pull(runtime, T0 + timedelta(hours=3)) == "unreachable"
        decision = runtime.ask(
            "cli",
            Things.artifacts(1)[0],
            EvidenceSet(),
            T0 + timedelta(hours=3),
            environment="production",
            scope_path=("acme",),
        )
        assert decision.state == "ALLOW" and "R202" not in decision.reason_codes

    @pytest.mark.parametrize("status", [404, 500, 503])
    def test_any_answer_that_is_not_a_bundle_or_a_304_is_unreachable_and_changes_nothing(
        self, tmp_path: Path, status: int
    ) -> None:
        _platform, store, runtime, puller = World.point(tmp_path)
        puller.pull(runtime, T0)
        store.status = status
        assert (
            puller.pull(runtime, T0 + timedelta(minutes=1)) == "unreachable"
            and runtime.held["version"] == 1
        )  # type: ignore[index]


class TestThePin:
    def test_a_point_pinned_to_a_version_does_not_take_a_later_one(self, tmp_path: Path) -> None:
        _platform, _store, runtime, puller = World.point(tmp_path, bundles=3, pin=2)
        assert puller.pull(runtime, T0) == "new" and runtime.held["version"] == 2  # type: ignore[index]
        assert (
            puller.pull(runtime, T0 + timedelta(minutes=1)) == "pinned"
            and runtime.held["version"] == 2
        )  # type: ignore[index]

    def test_lifting_the_pin_takes_the_bundles_it_held_back(self, tmp_path: Path) -> None:
        _platform, store, runtime, puller = World.point(tmp_path, bundles=3, pin=2)
        puller.pull(runtime, T0)
        free = BundlePuller("https://bundles.example/v1/policy", store.fetch, LocalStore(tmp_path))
        assert (
            free.pull(runtime, T0 + timedelta(minutes=1)) == "new" and runtime.held["version"] == 3
        )  # type: ignore[index]


class TestWhatIsRefused:
    def test_a_bundle_signed_by_a_key_nobody_delegated_is_refused_and_the_held_one_stays(
        self, tmp_path: Path
    ) -> None:
        platform, store, runtime, puller = World.point(tmp_path)
        puller.pull(runtime, T0)
        stranger = Platform(policy_key=Ed25519Signer(Kit.seed("a stranger")))
        stranger.root = platform.root
        expires = T0 + timedelta(days=2)
        forged = stranger.publish(Kit.compiled(2, expires), issued=T0, expires=expires)
        store.body = json.dumps({"bundles": [forged]}).encode()
        store.generation += 1
        with pytest.raises(BundleError):
            puller.pull(runtime, T0 + timedelta(minutes=1))
        assert runtime.held["version"] == 1  # type: ignore[index]

    @pytest.mark.parametrize("body", [b"not json", b'{"nothing": []}', b'{"bundles": "x"}', b"[]"])
    def test_an_answer_that_is_not_a_list_of_bundles_is_refused(
        self, tmp_path: Path, body: bytes
    ) -> None:
        _platform, store, runtime, puller = World.point(tmp_path)
        store.body = body
        with pytest.raises(BundleError):
            puller.pull(runtime, T0)
        assert runtime.held is None

    def test_a_replayed_older_bundle_is_refused_by_name(self, tmp_path: Path) -> None:
        platform, store, runtime, puller = World.point(tmp_path, bundles=2)
        puller.pull(runtime, T0)
        store.body = json.dumps({"bundles": [platform.chain[0]]}).encode()
        store.status = 200
        with pytest.raises(BundleRefused) as caught:
            BundlePuller(
                "https://bundles.example/v1/policy", store.fetch, LocalStore(tmp_path / "other")
            ).pull(runtime, T0)
        assert caught.value.name == BundleRefused.ROLLED_BACK
