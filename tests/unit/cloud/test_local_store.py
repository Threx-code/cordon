"""Row BP-2-6, the store half: what a point keeps on disk to decide and report with no network.

Each part is tested for what it promises: a write is whole or absent, a blob that no longer matches its digest is not read, a
cache entry that is not what was written is a miss, and the outbox keeps its order, deduplicates by id, counts what it refuses and
sends nothing twice from one drain.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud.local_store import LocalStore, Pending
from cordon_scanner.contracts.digests import ArtifactDigests


class Kit:
    @staticmethod
    def key(label: str) -> str:
        return ArtifactDigests.of_bytes(label.encode())

    @staticmethod
    def decision(key: str, **more: Any) -> dict[str, Any]:
        return {"state": "ALLOW", "inputs_digest": key, **more}


class Receiver:
    """The control plane as the outbox sees it: deduplicates on the id, can be made to fail on a given upload."""

    def __init__(self, fail_on: int | None = None) -> None:
        self.received: list[Pending] = []
        self.fail_on = fail_on
        self.calls = 0

    def __call__(self, item: Pending) -> None:
        self.calls += 1
        if self.fail_on is not None and self.calls == self.fail_on:
            raise ConnectionError("down")
        if item.id not in {seen.id for seen in self.received}:
            self.received.append(item)


class TestTheBundle:
    def test_what_was_kept_is_what_comes_back(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        assert store.load_bundle() is None
        store.save_bundle([{"payload": "a"}])
        assert store.load_bundle() == [{"payload": "a"}]
        store.save_bundle([{"payload": "b"}])
        assert LocalStore(tmp_path).load_bundle() == [{"payload": "b"}]

    def test_a_damaged_file_is_nothing_kept(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        store.save_bundle([{"payload": "a"}])
        (tmp_path / "bundle" / "chain.json").write_bytes(b'[{"payl')
        assert store.load_bundle() is None


class TestBlobs:
    def test_a_rule_pack_comes_back_with_its_digest_and_time(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        digest = store.put_blob("rulepack", "core.v2", b"pack bytes", "2026-11-19T08:00:00Z")
        blob = store.blob("rulepack", "core.v2")
        assert blob is not None and blob.data == b"pack bytes"
        assert blob.digest == digest == "sha256:" + hashlib.sha256(b"pack bytes").hexdigest()
        assert blob.issued_at == "2026-11-19T08:00:00Z"

    def test_bytes_that_no_longer_match_their_digest_are_not_read(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        store.put_blob("intel", "snapshot", b"snapshot", "2026-11-19T08:00:00Z")
        (tmp_path / "blobs" / "intel-snapshot.bin").write_bytes(b"snapshoT")
        assert store.blob("intel", "snapshot") is None

    def test_an_absent_blob_is_none(self, tmp_path: Path) -> None:
        assert LocalStore(tmp_path).blob("intel", "snapshot") is None

    @pytest.mark.parametrize("name", ["", "../up", "a/b", "A", "x" * 65, ".hidden"])
    def test_a_name_that_could_leave_the_folder_is_refused(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(ValueError):
            LocalStore(tmp_path).put_blob("rulepack", name, b"x", "2026-11-19T08:00:00Z")

    def test_an_unknown_kind_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            LocalStore(tmp_path).put_blob("secrets", "x", b"x", "2026-11-19T08:00:00Z")


class TestTheDecisionCache:
    def test_a_decision_comes_back_under_its_key(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        key = Kit.key("one")
        assert store.cache_get(key) is None
        store.cache_put(key, Kit.decision(key))
        assert store.cache_get(key) == Kit.decision(key)

    def test_a_decision_is_kept_only_under_its_own_inputs_digest(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            LocalStore(tmp_path).cache_put(Kit.key("one"), Kit.decision(Kit.key("two")))

    def test_a_key_that_is_not_a_digest_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            LocalStore(tmp_path).cache_get("../../etc/passwd")

    def test_an_entry_that_is_not_what_was_written_is_a_miss_and_is_removed(
        self, tmp_path: Path
    ) -> None:
        store = LocalStore(tmp_path)
        key, other = Kit.key("one"), Kit.key("two")
        store.cache_put(key, Kit.decision(key))
        path = tmp_path / "decisions" / f"{key.partition(':')[2]}.json"
        path.write_bytes(b'{"key":"' + other.encode() + b'","decision":{}}')
        assert store.cache_get(key) is None
        assert not path.exists()

    def test_the_cache_is_bounded_and_drops_its_oldest(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path, max_cache=10)
        keys = [Kit.key(str(number)) for number in range(128)]
        for key in keys:
            store.cache_put(key, Kit.decision(key))
        assert store.cache_size() <= 10 + 63
        assert store.cache_get(keys[-1]) is not None
        assert store.cache_get(keys[0]) is None


class TestTheOutbox:
    def test_uploads_come_back_in_the_order_they_went_in_with_their_ids(
        self, tmp_path: Path
    ) -> None:
        store = LocalStore(tmp_path)
        for body in (b"first", b"second", b"third"):
            assert store.enqueue("decision", body)
        waiting = store.pending()
        assert [item.body for item in waiting] == [b"first", b"second", b"third"]
        assert [item.sequence for item in waiting] == [1, 2, 3]
        assert waiting[0].id == hashlib.sha256(b"first").hexdigest()

    def test_the_queue_survives_a_restart(self, tmp_path: Path) -> None:
        LocalStore(tmp_path).enqueue("decision", b"kept")
        again = LocalStore(tmp_path)
        assert [item.body for item in again.pending()] == [b"kept"]
        again.enqueue("decision", b"after")
        assert [item.sequence for item in again.pending()] == [1, 2]

    def test_a_drain_sends_everything_oldest_first_and_empties_the_queue(
        self, tmp_path: Path
    ) -> None:
        store = LocalStore(tmp_path)
        for number in range(5):
            store.enqueue("decision", f"d{number}".encode())
        receiver = Receiver()
        drained = store.drain(receiver)
        assert (drained.sent, drained.left) == (5, 0)
        assert [item.body for item in receiver.received] == [f"d{n}".encode() for n in range(5)]
        assert store.pending() == []

    def test_a_failure_stops_the_drain_and_keeps_that_upload_and_the_rest(
        self, tmp_path: Path
    ) -> None:
        store = LocalStore(tmp_path)
        for number in range(5):
            store.enqueue("decision", f"d{number}".encode())
        receiver = Receiver(fail_on=3)
        first = store.drain(receiver)
        assert (first.sent, first.left) == (2, 3)
        assert [item.body for item in store.pending()] == [b"d2", b"d3", b"d4"]
        second = store.drain(receiver)
        assert (second.sent, second.left) == (3, 0)
        assert [item.body for item in receiver.received] == [f"d{n}".encode() for n in range(5)]

    def test_a_full_outbox_refuses_and_counts_and_keeps_what_it_has(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path, max_pending=3)
        results = [store.enqueue("decision", f"d{n}".encode()) for n in range(5)]
        assert results == [True, True, True, False, False]
        assert store.refused() == 2
        assert [item.body for item in store.pending()] == [b"d0", b"d1", b"d2"]
        store.drain(Receiver())
        assert store.enqueue("decision", b"again") and store.refused() == 2

    def test_a_damaged_upload_is_not_sent_as_something_it_is_not(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        store.enqueue("decision", b"good")
        store.enqueue("decision", b"to be damaged")
        damaged = sorted((tmp_path / "outbox").glob("*.upload"))[1]
        damaged.write_bytes(b"something else")
        assert [item.body for item in store.pending()] == [b"good"]

    def test_a_write_that_never_finished_is_not_an_upload(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        store.enqueue("decision", b"whole")
        (tmp_path / "outbox" / ("0" * 11 + "2-decision-" + "a" * 64 + ".upload.tmp")).write_bytes(
            b"half"
        )
        assert [item.body for item in store.pending()] == [b"whole"]

    def test_the_kind_of_an_upload_is_checked(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            LocalStore(tmp_path).enqueue("../x", b"x")
