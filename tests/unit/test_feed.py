"""The signed intel feed: what is accepted, what is refused, and what a scan reports.

Every refusal here is an attack with a name: rollback, freeze, mix-and-match, a forged or
under-signed role, an unauthorised root rotation. A refused update must leave the last verified
intel exactly as it was.
"""

from __future__ import annotations

import pytest

import feedkit
from cordon_scanner.intel import advisories, feed
from cordon_scanner.intel.feed import Feed, FeedError, FeedState
from feedkit import NOW, SignedFeed, delta, full_bundle

RECORD = {
    "id": "MAL-2027-0001",
    "name": "event-strem",
    "versions": ["1.0.3"],
    "malicious": True,
    "summary": "typosquat of event-stream",
}
NEWER = {**RECORD, "id": "MAL-2027-0002", "name": "left-padd", "summary": "typosquat of left-pad"}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("CORDON_OFFLINE", raising=False)
    advisories.ShippedAdvisories.reset_caches()
    yield
    advisories.ShippedAdvisories.reset_caches()


def _matches(name: str, version: str) -> bool:
    advisories.ShippedAdvisories.reset_caches()
    return bool(advisories.AdvisoryDatabase.bundled().matching("npm", name, version))


class TestTheSigner:
    def test_rfc_8032_test_one(self) -> None:
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        assert feedkit.public_key(seed).hex() == (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        assert feedkit.sign(seed, b"").hex() == (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )


class TestAFreshClient:
    def test_the_full_bundle_then_deltas_are_applied(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(
            2,
            full=(1, full_bundle({"npm": [RECORD]})),
            deltas={2: delta(2, {"npm": {"upsert": [NEWER]}})},
        )

        state = test_feed.client().update()

        assert state.serial == 2
        assert _matches("event-strem", "1.0.3")
        assert _matches("left-padd", "1.0.3")

    def test_the_next_update_takes_only_the_new_delta(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))
        test_feed.client().update()
        test_feed.requests.clear()

        test_feed.publish(
            2,
            full=(1, full_bundle({"npm": [RECORD]})),
            deltas={2: delta(2, {"npm": {"upsert": [NEWER]}})},
        )
        test_feed.client().update()

        fetched = [name for name, _ in test_feed.requests]
        assert "deltas/2.json.gz" in fetched
        assert not any(name.startswith("full/") for name in fetched)
        assert _matches("left-padd", "1.0.3")

    def test_a_withdrawal_removes_the_record(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))
        test_feed.client().update()
        test_feed.publish(2, deltas={2: delta(2, {"npm": {"withdraw": [RECORD["id"]]}})})

        test_feed.client().update()

        assert not _matches("event-strem", "1.0.3")

    def test_metadata_is_fetched_with_the_three_second_timeout(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))
        test_feed.client().update()

        timeouts = dict(test_feed.requests)
        assert timeouts["timestamp.json"] == feed.METADATA_TIMEOUT == 3.0


class TestRefusals:
    def _at_serial_five(self) -> SignedFeed:
        test_feed = SignedFeed()
        test_feed.publish(5, full=(5, full_bundle({"npm": [RECORD]})), version=10)
        test_feed.client().update()
        return test_feed

    def test_an_older_serial_is_a_rollback(self) -> None:
        test_feed = self._at_serial_five()
        test_feed.publish(3, full=(3, full_bundle({"npm": []})), version=11)

        with pytest.raises(FeedError, match="rollback"):
            test_feed.client().update()
        assert FeedState.load(feed.FeedStore.state_dir()).serial == 5
        assert _matches("event-strem", "1.0.3")

    def test_an_older_timestamp_version_is_a_rollback(self) -> None:
        test_feed = self._at_serial_five()
        test_feed.publish(5, full=(5, full_bundle({"npm": [RECORD]})), version=9)

        with pytest.raises(FeedError, match="rollback"):
            test_feed.client().update()

    def test_an_expired_timestamp_is_a_freeze(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(
            1, full=(1, full_bundle({"npm": [RECORD]})), expires="2026-01-01T00:00:00Z"
        )

        with pytest.raises(FeedError, match="freeze"):
            test_feed.client().update()

    def test_a_swapped_delta_fails_its_pin_and_nothing_is_applied(self) -> None:
        test_feed = self._at_serial_five()
        test_feed.publish(6, deltas={6: delta(6, {"npm": {"upsert": [NEWER]}})})
        test_feed.files["deltas/6.json.gz"] = delta(6, {"npm": {"withdraw": [RECORD["id"]]}})

        with pytest.raises(FeedError, match=r"sha256|length"):
            test_feed.client().update()
        assert FeedState.load(feed.FeedStore.state_dir()).serial == 5
        assert _matches("event-strem", "1.0.3")
        assert not _matches("left-padd", "1.0.3")

    def test_metadata_signed_by_the_wrong_key_is_refused(self) -> None:
        test_feed = SignedFeed()
        test_feed.timestamp_key = feedkit.new_key("attacker")
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))
        honest_root = SignedFeed().root()

        with pytest.raises(FeedError, match="signed by 0 of the 1"):
            test_feed.client(root=honest_root).update()

    def test_a_threshold_of_two_needs_two_keys(self) -> None:
        test_feed = SignedFeed()
        second = feedkit.new_key("timestamp-2")
        roles = test_feed.roles()
        roles["timestamp"] = ([test_feed.timestamp_key, second], 2)
        root = feedkit.signed(feedkit.root_body(1, roles), test_feed.root_key)
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))

        with pytest.raises(FeedError, match="1 of the 2"):
            test_feed.client(root=root).update()


class TestRootRotation:
    def test_a_root_signed_by_old_and_new_keys_is_followed(self) -> None:
        test_feed = SignedFeed()
        new_root_key = feedkit.new_key("root-2")
        new_timestamp_key = feedkit.new_key("timestamp-rotated")
        roles = test_feed.roles()
        roles["root"] = ([new_root_key], 1)
        roles["timestamp"] = ([new_timestamp_key], 1)
        test_feed.files["2.root.json"] = feed.FeedRoles.canonical(
            feedkit.signed(feedkit.root_body(2, roles), test_feed.root_key, new_root_key)
        )
        test_feed.timestamp_key = new_timestamp_key
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))

        test_feed.client().update()

        stored = FeedState.load(feed.FeedStore.state_dir()).root
        assert stored is not None and stored["signed"]["version"] == 2

    def test_a_root_not_signed_by_the_old_keys_is_refused(self) -> None:
        test_feed = SignedFeed()
        usurper = feedkit.new_key("usurper")
        roles = test_feed.roles()
        roles["root"] = ([usurper], 1)
        test_feed.files["2.root.json"] = feed.FeedRoles.canonical(
            feedkit.signed(feedkit.root_body(2, roles), usurper)
        )
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))

        with pytest.raises(FeedError, match="root"):
            test_feed.client().update()


class TestStatus:
    def test_a_build_without_a_pinned_root_makes_no_request(self) -> None:
        calls: list[str] = []
        unpinned = Feed(root=None, fetch=lambda url, *_: calls.append(url) or b"")

        result = feed.FeedClient.status(use_feed=True, max_age=None, feed=unpinned, now=NOW)

        assert calls == []
        assert not result.feed_enabled
        assert not result.stale  # no feed, no default staleness check
        assert result.source in ("package", "bundle")

    def test_offline_makes_no_request(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))

        result = feed.FeedClient.status(
            use_feed=False, max_age=None, feed=test_feed.client(), now=NOW
        )

        assert test_feed.requests == []
        assert not result.refreshed

    def test_a_refresh_reports_the_feed_as_the_source(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))

        result = feed.FeedClient.status(
            use_feed=True, max_age=None, feed=test_feed.client(), now=NOW
        )

        assert result.refreshed and result.source == "feed"
        assert result.age_seconds == 0 and not result.stale

    def test_an_unreachable_feed_leaves_old_intel_that_goes_stale(self) -> None:
        test_feed = SignedFeed()
        test_feed.publish(1, full=(1, full_bundle({"npm": [RECORD]})))
        test_feed.client().update()

        def unreachable(*_args):
            raise FeedError("the feed could not be reached (URLError)")

        two_days_later = NOW + 2 * 24 * 3600
        result = feed.FeedClient.status(
            use_feed=True,
            max_age=None,
            feed=test_feed.client(fetch=unreachable),
            now=two_days_later,
        )

        assert not result.refreshed
        assert result.stale and result.age_seconds == 2 * 24 * 3600
        assert "could not be reached" in result.error
        assert _matches("event-strem", "1.0.3")

    def test_an_explicit_limit_applies_without_a_feed(self) -> None:
        result = feed.FeedClient.status(
            use_feed=False, max_age=60, feed=Feed(root=None), now=NOW + 10**9
        )
        assert result.stale

    def test_zero_turns_the_check_off(self) -> None:
        test_feed = SignedFeed()
        result = feed.FeedClient.status(
            use_feed=False, max_age=0, feed=test_feed.client(), now=NOW + 10**9
        )
        assert not result.stale

    @pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
    def test_cordon_offline_is_recognised(self, value) -> None:
        assert feed.FeedClient.offline_requested({"CORDON_OFFLINE": value})

    def test_cordon_offline_unset_is_online(self) -> None:
        assert not feed.FeedClient.offline_requested({})


class TestAScanReportsItsIntel:
    def test_the_result_carries_the_intel_and_a_stale_scan_is_incomplete(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        (tmp_path / "ok.py").write_text("x = 1\n")
        config = Config.default().with_overrides(use_cache=False, max_intel_age=1)

        result = Scanner(config).scan(tmp_path)

        assert result.intel is not None
        assert result.intel["stale"] is True
        assert not result.complete
        assert any(f.rule_id == "OPERATIONAL.INTEL.STALE" for f in result.findings)
        assert "intel" in result.to_dict()

    def test_the_default_is_not_stale_without_a_feed(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        (tmp_path / "ok.py").write_text("x = 1\n")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)

        assert result.intel is not None and result.intel["feed_enabled"] is False
        assert not any(f.rule_id == "OPERATIONAL.INTEL.STALE" for f in result.findings)
