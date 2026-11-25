"""Row BP-6-12 (and, at the end, BP-15-15's scanner half: the decision delegation under a customer root): a point pulls its bundle from the bundle store with an ETag and a version pin.

The fake store answers as the platform's `GET /v1/bundles/<scope>` does: `304` with no body when nothing is newer than `since`, otherwise
the API's standard envelope with the chain since that version (or, when it no longer holds the chain, `restart: true` and the newest
bundle alone), an `ETag` that is the quoted payload sha256, and an `X-Bundle-Version`. Each of the four points (the CLI, the hooks,
the firewall, the gates) pulls a bundle, keeps it, and revalidates; a bundle held and not yet expired still decides when the store
cannot be reached; a pin holds a point at a version.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud.agent.decision_delegation import (
    DECISION_DELEGATION_SCHEMA,
    DECISION_DELEGATION_TYPE,
)
from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, BundleRefused, Dsse
from cordon_scanner.cloud.bundle_puller import BundlePuller
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.decide.decision.evidence import EvidenceSet
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, TENANT, Kit, Platform, Things

POINTS = ("cli", "agent_hook", "firewall", "ci_gate")
URL = "https://bundles.example/v1/bundles/org:acme"


class BundleStore:
    """The control plane's bundle store as the puller sees it."""

    def __init__(self, platform: Platform) -> None:
        self.platform = platform
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.down = False
        self.status = 200
        self.body: bytes | None = None
        self.restart = False
        self.newest: dict[str, Any] | None = None

    def latest(self) -> int:
        return len(self.platform.chain)

    def etag(self) -> str:
        return '"' + BundleChain.payload_sha(self.platform.payloads[-1]) + '"'

    def fetch(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((url, dict(headers)))
        if self.down:
            raise ConnectionError("the bundle store is down")
        if self.status != 200:
            return self.status, {}, json.dumps({"status": False, "message": "refused"}).encode()
        since = int(url.split("since=", 1)[1].split("&", 1)[0])
        answer = {"ETag": self.etag(), "X-Bundle-Version": str(self.latest())}
        if since >= self.latest() or headers.get("If-None-Match") == self.etag():
            return 304, answer, b""
        newest = self.newest or self.platform.chain[-1]
        data: dict[str, Any] = {
            "scope": "org:acme",
            "from_version": since,
            "latest_version": self.latest(),
            "etag": self.etag().strip('"'),
            "restart": self.restart,
            "bundles": [] if self.restart else self.platform.chain[since:],
        }
        if self.restart:
            data["latest"] = newest
        body = self.body or json.dumps({"status": True, "message": "ok", "data": data}).encode()
        return 200, answer, body


class Point:
    def __init__(
        self, tmp_path: Path, bundles: int = 1, pin: int | None = None, wait_s: int = 0
    ) -> None:
        self.platform = Platform()
        for _ in range(bundles):
            self.publish()
        self.store = BundleStore(self.platform)
        self.local = LocalStore(tmp_path)
        self.runtime = Kit.runtime(self.platform, self.local)
        self.puller = BundlePuller(URL, self.store.fetch, self.local, pin=pin, wait_s=wait_s)

    def publish(self) -> None:
        expires = T0 + timedelta(days=2)
        self.platform.publish(
            Kit.compiled(len(self.platform.chain) + 1, expires), issued=T0, expires=expires
        )

    def held(self) -> int:
        assert self.runtime.held is not None
        version: int = self.runtime.held["version"]
        return version

    def ask(self, point: str, minutes: int) -> Any:
        return self.runtime.ask(
            point,
            Things.artifacts(1)[0],
            EvidenceSet(),
            T0 + timedelta(minutes=minutes),
            environment="production",
            scope_path=("acme",),
        )

    @staticmethod
    def stranger_chain(platform: Platform, versions: int) -> Platform:
        """A platform under the same root whose policy key was never delegated."""
        other = Platform(policy_key=Ed25519Signer(Kit.seed("a stranger")))
        other.root = platform.root
        expires = T0 + timedelta(days=2)
        for number in range(versions):
            other.publish(Kit.compiled(number + 1, expires), issued=T0, expires=expires)
        return other


class TestEachPointPullsKeepsAndRevalidates:
    @pytest.mark.parametrize("point", POINTS)
    def test_the_first_pull_takes_the_bundle_and_the_next_asks_with_the_etag_as_the_store_wrote_it(
        self, tmp_path: Path, point: str
    ) -> None:
        site = Point(tmp_path)
        assert site.puller.pull(site.runtime, T0) == "new" and site.held() == 1
        assert "If-None-Match" not in site.store.calls[0][1] and site.store.calls[0][0].endswith(
            "?since=0"
        )
        assert site.puller.pull(site.runtime, T0 + timedelta(minutes=5)) == "unchanged"
        sent = site.store.calls[1][1]["If-None-Match"]
        assert sent == site.store.etag() and sent.startswith('"') and sent.endswith('"')
        assert site.store.calls[1][0].endswith("?since=1")
        decision = site.ask(point, 6)
        assert decision.state == "ALLOW" and decision.policy.version == 1

    @pytest.mark.parametrize("point", POINTS)
    def test_a_restarted_point_still_revalidates_with_the_etag_it_kept(
        self, tmp_path: Path, point: str
    ) -> None:
        site = Point(tmp_path)
        site.puller.pull(site.runtime, T0)
        first = site.store.etag()
        again = Kit.runtime(site.platform, LocalStore(tmp_path))
        assert again.resume(T0 + timedelta(minutes=1))
        site.publish()
        pulled = BundlePuller(URL, site.store.fetch, LocalStore(tmp_path)).pull(
            again, T0 + timedelta(minutes=2)
        )
        assert pulled == "new" and site.store.calls[-1][1]["If-None-Match"] == first, point

    def test_a_new_bundle_is_taken_and_catching_up_takes_every_bundle_in_order(
        self, tmp_path: Path
    ) -> None:
        site = Point(tmp_path, bundles=3)
        assert site.puller.pull(site.runtime, T0) == "new" and site.held() == 3
        site.publish()
        assert (
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1)) == "new" and site.held() == 4
        )

    def test_a_long_poll_is_asked_for_and_bounded(self, tmp_path: Path) -> None:
        site = Point(tmp_path, wait_s=20)
        site.puller.pull(site.runtime, T0)
        assert site.store.calls[0][0].endswith("?since=0&wait=20")
        with pytest.raises(ValueError, match="30"):
            BundlePuller(URL, site.store.fetch, site.local, wait_s=31)


class TestARestartIsAFreshStart:
    def test_the_newest_bundle_alone_is_taken_when_the_store_no_longer_holds_the_chain(
        self, tmp_path: Path
    ) -> None:
        site = Point(tmp_path, bundles=5)
        site.store.restart = True
        assert site.puller.pull(site.runtime, T0) == "new" and site.held() == 5

    def test_a_point_holding_an_old_bundle_skips_ahead_to_it(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=2)
        site.puller.pull(site.runtime, T0)
        for _ in range(3):
            site.publish()
        site.store.restart = True
        assert (
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1)) == "new" and site.held() == 5
        )

    def test_it_is_verified_like_any_bundle_so_a_forged_one_is_refused_and_the_held_one_stays(
        self, tmp_path: Path
    ) -> None:
        site = Point(tmp_path, bundles=2)
        site.puller.pull(site.runtime, T0)
        forged = Point.stranger_chain(site.platform, 4)
        site.publish()
        site.store.restart, site.store.newest = True, forged.chain[-1]
        with pytest.raises(BundleError):
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1))
        assert site.held() == 2

    def test_it_is_never_older_than_the_bundle_held(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=3)
        site.puller.pull(site.runtime, T0)
        site.publish()
        site.store.restart, site.store.newest = True, site.platform.chain[1]
        with pytest.raises(BundleRefused) as caught:
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1))
        assert caught.value.name == BundleRefused.ROLLED_BACK and site.held() == 3

    def test_the_same_bundle_again_is_unchanged(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=2)
        site.puller.pull(site.runtime, T0)
        assert (
            site.runtime.restart(site.platform.chain[-1], T0 + timedelta(minutes=1)) == "unchanged"
        )

    def test_a_restart_that_sends_no_bundle_is_refused(self, tmp_path: Path) -> None:
        site = Point(tmp_path)
        site.store.restart = True
        site.store.body = json.dumps(
            {"status": True, "message": "ok", "data": {"restart": True, "bundles": []}}
        ).encode()
        with pytest.raises(BundleError, match="restart"):
            site.puller.pull(site.runtime, T0)


class TestAStaleCacheStillDecides:
    def test_with_the_store_down_a_held_bundle_that_has_not_expired_decides_as_before(
        self, tmp_path: Path
    ) -> None:
        site = Point(tmp_path)
        site.puller.pull(site.runtime, T0)
        site.store.down = True
        assert site.puller.pull(site.runtime, T0 + timedelta(hours=3)) == "unreachable"
        decision = site.ask("cli", 180)
        assert decision.state == "ALLOW" and "R202" not in decision.reason_codes

    @pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
    def test_any_answer_that_is_not_a_bundle_or_a_304_is_unreachable_and_changes_nothing(
        self, tmp_path: Path, status: int
    ) -> None:
        site = Point(tmp_path)
        site.puller.pull(site.runtime, T0)
        site.publish()
        site.store.status = status
        assert (
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1)) == "unreachable"
            and site.held() == 1
        )


class TestThePin:
    def test_a_point_pinned_to_a_version_does_not_take_a_later_one(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=3, pin=2)
        assert site.puller.pull(site.runtime, T0) == "new" and site.held() == 2
        assert (
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1)) == "pinned"
            and site.held() == 2
        )

    def test_lifting_the_pin_takes_the_bundles_it_held_back(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=3, pin=2)
        site.puller.pull(site.runtime, T0)
        free = BundlePuller(URL, site.store.fetch, LocalStore(tmp_path))
        assert free.pull(site.runtime, T0 + timedelta(minutes=1)) == "new" and site.held() == 3

    def test_a_restart_past_the_pin_is_not_taken(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=4, pin=2)
        site.store.restart = True
        assert site.puller.pull(site.runtime, T0) == "pinned" and site.runtime.held is None


class TestWhatIsRefused:
    def test_a_bundle_signed_by_a_key_nobody_delegated_is_refused_and_the_held_one_stays(
        self, tmp_path: Path
    ) -> None:
        site = Point(tmp_path)
        site.puller.pull(site.runtime, T0)
        forged = Point.stranger_chain(site.platform, 2)
        site.publish()
        site.store.body = json.dumps(
            {
                "status": True,
                "message": "ok",
                "data": {"restart": False, "bundles": [forged.chain[1]]},
            }
        ).encode()
        with pytest.raises(BundleError):
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1))
        assert site.held() == 1

    @pytest.mark.parametrize(
        "body",
        [
            b"not json",
            b"[]",
            b'{"status": false, "message": "no", "data": {"restart": false, "bundles": []}}',
            b'{"status": true, "message": "ok"}',
            b'{"status": true, "message": "ok", "data": {"bundles": []}}',
            b'{"status": true, "message": "ok", "data": {"restart": false, "bundles": "x"}}',
        ],
    )
    def test_an_answer_that_is_not_the_stores_standard_envelope_is_refused(
        self, tmp_path: Path, body: bytes
    ) -> None:
        site = Point(tmp_path)
        site.store.body = body
        with pytest.raises(BundleError):
            site.puller.pull(site.runtime, T0)
        assert site.runtime.held is None

    def test_a_replayed_older_bundle_is_refused_by_name(self, tmp_path: Path) -> None:
        site = Point(tmp_path, bundles=2)
        site.puller.pull(site.runtime, T0)
        site.publish()
        site.store.body = json.dumps(
            {
                "status": True,
                "message": "ok",
                "data": {"restart": False, "bundles": [site.platform.chain[0]]},
            }
        ).encode()
        with pytest.raises(BundleRefused) as caught:
            site.puller.pull(site.runtime, T0 + timedelta(minutes=1))
        assert caught.value.name == BundleRefused.ROLLED_BACK


DECIDER = Ed25519Signer(Kit.seed("puller-decider"))


class Served:
    """The platform's answers with the second link: a decision delegation per sequence, and the header on every answer."""

    def __init__(self, platform: Platform, store: BundleStore) -> None:
        self.platform, self.store, self.sequence, self.whole_calls = platform, store, 0, 0
        self.header = True

    def delegation(self, sequence: int, **changes: Any) -> dict[str, Any]:
        document = {
            "_type": DECISION_DELEGATION_SCHEMA,
            "tenant": TENANT,
            "issued_at": T0.isoformat(),
            "sequence": sequence,
            "root_keyid": Dsse.keyid(self.platform.root.public),
            "root_issued_at": T0.isoformat(),
            "policy_keyid": Dsse.keyid(self.platform.policy_key.public),
            "keys": [
                {
                    "role": "decision.cloud",
                    "version": 1,
                    "keyid": Dsse.keyid(DECIDER.public),
                    "public": DECIDER.public.hex(),
                    "not_before": (T0 - timedelta(hours=1)).isoformat(),
                    "valid_until": (T0 + timedelta(days=7)).isoformat(),
                }
            ],
            **changes,
        }
        return Platform.sign(DECISION_DELEGATION_TYPE, document, self.platform.policy_key)

    def fetch(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        if "since=" not in url:
            self.whole_calls += 1
            data = {"version": 1, "delegations": [self.delegation(self.sequence)]}
            body = json.dumps({"status": True, "message": "ok", "data": data}).encode()
            return 200, self.tag({}), body
        status, answered, body = self.store.fetch(url, headers)
        if status == 200:
            document = json.loads(body)
            document["data"]["delegations"] = (
                [self.delegation(self.sequence)] if self.sequence else []
            )
            body = json.dumps(document).encode()
        return status, self.tag(answered), body

    def tag(self, answered: dict[str, str]) -> dict[str, str]:
        return (
            {**answered, "X-Decision-Delegation-Sequence": str(self.sequence)}
            if self.header
            else dict(answered)
        )


class Site:
    def __init__(self, tmp_path: Path) -> None:
        self.point = Point(tmp_path)
        self.served = Served(self.point.platform, self.point.store)
        self.local = self.point.local
        self.puller = BundlePuller(
            URL,
            self.served.fetch,
            self.local,
            root_public=self.point.platform.root.public,
            delegation=self.point.platform.delegation(),
            tenant=TENANT,
        )

    def pull(self, minutes: int = 0) -> str:
        return self.puller.pull(self.point.runtime, T0 + timedelta(minutes=minutes))


class TestTheDelegationServedWithTheBundle:
    def test_a_delegation_in_the_answer_is_verified_and_kept(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.served.sequence = 3
        site.pull()
        assert site.puller.held_sequence() == 3 and site.puller.decision_delegation() is not None

    def test_the_kept_delegation_is_still_there_for_a_restarted_point(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.served.sequence = 3
        site.pull()
        again = BundlePuller(
            URL,
            site.served.fetch,
            LocalStore(tmp_path),
            root_public=site.point.platform.root.public,
            delegation=site.point.platform.delegation(),
            tenant=TENANT,
        )
        assert again.held_sequence() == 3

    def test_an_answer_with_no_delegation_keeps_what_is_held(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.served.sequence = 3
        site.pull()
        site.served.sequence = 0
        site.point.publish()
        site.pull(1)
        assert site.puller.held_sequence() == 3

    def test_a_delegation_signed_by_another_key_is_refused_and_nothing_is_kept(
        self, tmp_path: Path
    ) -> None:
        site = Site(tmp_path)
        site.served.sequence = 3
        stranger = Ed25519Signer(Kit.seed("puller-stranger"))
        site.served.platform = Platform(policy_key=stranger, root=site.point.platform.root)
        with pytest.raises(BundleError):
            site.pull()
        assert site.puller.held_sequence() == 0

    def test_a_lower_sequence_replayed_is_refused_and_the_higher_stays(
        self, tmp_path: Path
    ) -> None:
        site = Site(tmp_path)
        site.served.sequence = 5
        site.pull()
        site.served.sequence = 4
        site.point.publish()
        with pytest.raises(BundleError, match="older"):
            site.pull(1)
        assert site.puller.held_sequence() == 5

    def test_a_key_past_the_policy_keys_window_is_refused(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.served.sequence = 3
        short = Platform.sign(
            "application/vnd.cordon.delegation+json",
            {
                "_type": "cordon.delegation/v1",
                "tenant": TENANT,
                "issued_at": T0.isoformat(),
                "keys": [
                    {
                        "keyid": Dsse.keyid(site.point.platform.policy_key.public),
                        "public": site.point.platform.policy_key.public.hex(),
                        "role": "policy",
                        "not_before": (T0 - timedelta(days=1)).isoformat(),
                        "valid_until": (T0 + timedelta(days=1)).isoformat(),
                        "version": 1,
                    }
                ],
            },
            site.point.platform.root,
        )
        puller = BundlePuller(
            URL,
            site.served.fetch,
            site.local,
            root_public=site.point.platform.root.public,
            delegation=short,
            tenant=TENANT,
        )
        with pytest.raises(BundleError, match="past the policy key"):
            puller.pull(site.point.runtime, T0)
        assert puller.held_sequence() == 0


class TestTheHeaderOnAnUnchangedBundle:
    def test_a_304_with_a_higher_sequence_fetches_the_whole_bundle_and_keeps_the_delegation(
        self, tmp_path: Path
    ) -> None:
        site = Site(tmp_path)
        site.served.sequence = 1
        site.pull()
        assert site.served.whole_calls == 0
        site.served.sequence = 2
        assert site.pull(1) == "unchanged"
        assert site.served.whole_calls == 1 and site.puller.held_sequence() == 2

    def test_a_304_with_an_equal_sequence_does_not_fetch(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.served.sequence = 2
        site.pull()
        assert site.pull(1) == "unchanged"
        assert site.served.whole_calls == 0

    def test_a_304_with_a_lower_sequence_does_not_fetch(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.served.sequence = 2
        site.pull()
        site.served.sequence = 1
        assert site.pull(1) == "unchanged"
        assert site.served.whole_calls == 0

    def test_a_header_that_is_not_a_number_is_ignored(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        site.pull()
        site.served.tag = lambda answered: {**answered, "X-Decision-Delegation-Sequence": "9; drop"}  # type: ignore[method-assign]
        assert site.pull(1) == "unchanged" and site.served.whole_calls == 0

    def test_a_header_with_a_forged_delegation_behind_it_keeps_what_is_held(
        self, tmp_path: Path
    ) -> None:
        site = Site(tmp_path)
        site.served.sequence = 1
        site.pull()
        site.served.sequence = 9
        site.served.delegation = lambda sequence, **c: Platform.sign(  # type: ignore[method-assign]
            DECISION_DELEGATION_TYPE,
            {"_type": DECISION_DELEGATION_SCHEMA, "sequence": sequence},
            Ed25519Signer(Kit.seed("forger")),
        )
        with pytest.raises(BundleError):
            site.pull(1)
        assert site.puller.held_sequence() == 1

    def test_a_puller_given_no_root_never_fetches_for_the_header(self, tmp_path: Path) -> None:
        site = Site(tmp_path)
        plain = BundlePuller(URL, site.served.fetch, site.local)
        site.served.sequence = 7
        plain.pull(site.point.runtime, T0)
        assert site.served.whole_calls == 0 and plain.held_sequence() == 0
