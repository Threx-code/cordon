"""`intel status`, `intel update` and `intel acquire`: what is printed, and which exit code says the intel
is stale, refused offline or could not be fetched (`cli/commands/intel.py`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.intel import IntelCommand
from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.intel.malware import feed


class _Kit:
    @staticmethod
    def status(**over: Any) -> Any:
        base: dict[str, Any] = {
            "source": "signed feed",
            "serial": 12,
            "age_seconds": 3 * 3600 + 5 * 60,
            "stale": False,
            "feed_enabled": True,
            "error": "",
            "refreshed": False,
            "osv_current": False,
        }
        current = SimpleNamespace(**{**base, **over})
        current.to_dict = lambda: {"source": current.source, "serial": current.serial}
        return current


status = _Kit.status


class TestStatusAndUpdate:
    @staticmethod
    def _feed(monkeypatch: pytest.MonkeyPatch, current: Any, offline: bool = False) -> list[Any]:
        asked: list[Any] = []
        monkeypatch.setattr(
            feed.FeedClient,
            "status",
            staticmethod(lambda use_feed, max_age: asked.append(use_feed) or current),
        )
        monkeypatch.setattr(feed.FeedClient, "offline_requested", staticmethod(lambda: offline))
        return asked

    @staticmethod
    def _run(action: str | None, json_: bool = False) -> int:
        return IntelCommand.run(argparse.Namespace(intel_command=action, json=json_))

    def test_a_missing_or_unknown_action_is_a_config_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert self._run(None) == int(ExitCode.CONFIG_ERROR)
        assert self._run("restart") == int(ExitCode.CONFIG_ERROR)
        assert "intel needs status, update or acquire" in capsys.readouterr().err

    def test_acquire_is_handed_to_the_release_history_step(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(IntelCommand, "acquire", classmethod(lambda cls, args: 42))
        assert self._run("acquire") == 42

    def test_status_prints_source_serial_age_and_feed_without_fetching(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        asked = self._feed(monkeypatch, status(stale=True, error="clock skew"))
        assert self._run("status") == int(ExitCode.CLEAN)
        assert asked == [False]
        assert capsys.readouterr().out.splitlines() == [
            "source:  signed feed (serial 12)",
            "age:     3h 5m -- STALE",
            "feed:    enabled",
            "note:    clock skew",
        ]

    def test_an_unknown_age_and_a_build_without_the_feed_are_said_plainly(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._feed(monkeypatch, status(serial=0, age_seconds=None, feed_enabled=False))
        assert self._run("status") == int(ExitCode.CLEAN)
        assert capsys.readouterr().out.splitlines() == [
            "source:  signed feed",
            "age:     unknown",
            "feed:    not available in this build",
        ]

    def test_json_status_is_the_state_as_sorted_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._feed(monkeypatch, status())
        assert self._run("status", json_=True) == int(ExitCode.CLEAN)
        assert json.loads(capsys.readouterr().out) == {"serial": 12, "source": "signed feed"}

    def test_an_update_that_refreshed_or_found_osv_current_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self._feed(monkeypatch, status(refreshed=True))
        assert self._run("update") == int(ExitCode.CLEAN)
        self._feed(monkeypatch, status(osv_current=True))
        assert self._run("update") == int(ExitCode.CLEAN)
        assert asked == [True]

    def test_an_update_no_source_could_do_exits_with_a_scanner_error_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._feed(monkeypatch, status())
        assert self._run("update") == int(ExitCode.SCANNER_ERROR)
        assert "no source could refresh the intel" in capsys.readouterr().err
        self._feed(monkeypatch, status(error="signature did not verify"))
        assert self._run("update") == int(ExitCode.SCANNER_ERROR)
        assert "no source could refresh" not in capsys.readouterr().err
        self._feed(monkeypatch, status())
        assert self._run("update", json_=True) == int(ExitCode.SCANNER_ERROR)
        assert "no source could refresh" not in capsys.readouterr().err

    def test_an_update_is_refused_offline_but_a_status_is_not(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._feed(monkeypatch, status(), offline=True)
        with pytest.raises(ConfigError, match="CORDON_OFFLINE is set"):
            self._run("update")
        assert self._run("status") == int(ExitCode.CLEAN)


class TestAcquire:
    @staticmethod
    def _world(
        monkeypatch: pytest.MonkeyPatch,
        identity: tuple[str, str, str] | None,
        read_ecosystems: tuple[str, ...] = (),
        release_ecosystems: tuple[str, ...] = ("pypi",),
        baseline: Any = None,
        record_error: Exception | None = None,
        baseline_error: Exception | None = None,
    ) -> list[Any]:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.engine.pipeline.history import History
        from cordon_scanner.intel.registries.record_sources.acquire import RecordAcquire
        from cordon_scanner.intel.registries.registry_record import RegistryRecord
        from cordon_scanner.intel.registries.release_history import ReleaseHistory
        from cordon_scanner.sources.archive import ArchiveReader

        calls: list[Any] = []
        monkeypatch.setattr(feed.FeedClient, "offline_requested", staticmethod(lambda: False))
        monkeypatch.setattr(
            ArchiveReader, "walk_archive", staticmethod(lambda data, path: [("f.py", b"x = 1")])
        )
        monkeypatch.setattr(
            History, "history_distribution", staticmethod(lambda units: "wheel" if identity else "")
        )
        monkeypatch.setattr(History, "history_identity", staticmethod(lambda units, d: identity))
        monkeypatch.setattr(RegistryRecord, "ECOSYSTEMS_READ", frozenset(read_ecosystems))
        monkeypatch.setattr(ReleaseHistory, "ecosystems", staticmethod(lambda: release_ecosystems))
        monkeypatch.setattr(
            EcosystemRegistry, "declared_dependencies", staticmethod(lambda units, d: {"b", "a"})
        )

        def record(*identity_: str, token: Any = None) -> None:
            calls.append(("record", identity_, token))
            if record_error:
                raise record_error

        def acquire(*identity_: str, current_dependencies: Any, reader: Any) -> Any:
            calls.append(("baseline", identity_, current_dependencies))
            if baseline_error:
                raise baseline_error
            return baseline

        monkeypatch.setattr(RecordAcquire, "acquire", staticmethod(record))
        monkeypatch.setattr(ReleaseHistory, "acquire", staticmethod(acquire))
        return calls

    @staticmethod
    def _baseline(version: str = "1.0", files: int = 3) -> Any:
        return SimpleNamespace(
            baseline_version=version, baseline_published="2025-01-02T03:04:05Z", files=range(files)
        )

    @staticmethod
    def _run(tmp_path: Path, json_: bool = False, targets: list[str] | None = None) -> int:
        archive = tmp_path / "pkg-2.0-py3-none-any.whl"
        archive.write_bytes(b"not read: the archive walk is stubbed")
        return IntelCommand.acquire(
            argparse.Namespace(targets=targets or [str(archive)], json=json_)
        )

    def test_a_release_with_a_baseline_is_compared_and_its_dependencies_passed_on_sorted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        calls = self._world(monkeypatch, ("pypi", "pkg", "2.0"), baseline=self._baseline())
        assert self._run(tmp_path) == int(ExitCode.CLEAN)
        assert calls == [("baseline", ("pypi", "pkg", "2.0"), ("a", "b"))]
        assert capsys.readouterr().out == "pkg@2.0: compared with 1.0 (2025-01-02, 3 files)\n"

    def test_a_release_with_no_older_baseline_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._world(monkeypatch, ("pypi", "pkg", "2.0"), baseline=self._baseline(version=""))
        assert self._run(tmp_path) == int(ExitCode.CLEAN)
        assert capsys.readouterr().out == "pkg@2.0: no release at least 90 days older\n"

    def test_the_registry_record_is_fetched_with_the_users_token_for_ecosystems_that_read_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CORDON_GITHUB_TOKEN", "t0k3n")
        calls = self._world(
            monkeypatch,
            ("pypi", "pkg", "2.0"),
            read_ecosystems=("pypi",),
            baseline=self._baseline(),
        )
        assert self._run(tmp_path) == int(ExitCode.CLEAN)
        assert calls[0] == ("record", ("pypi", "pkg", "2.0"), "t0k3n")

    def test_a_registry_that_cannot_answer_for_the_record_fails_the_run_but_not_the_comparison(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cordon_scanner.intel.registries.registry_client import RegistryError

        monkeypatch.delenv("CORDON_GITHUB_TOKEN", raising=False)
        calls = self._world(
            monkeypatch,
            ("pypi", "pkg", "2.0"),
            read_ecosystems=("pypi",),
            baseline=self._baseline(),
            record_error=RegistryError("503"),
        )
        assert self._run(tmp_path) == int(ExitCode.SCANNER_ERROR)
        assert calls[0][2] is None and calls[1][0] == "baseline"
        out = capsys.readouterr().out.splitlines()
        assert out[0].endswith("whl: could not acquire: 503")
        assert "compared with 1.0" in out[1]

    def test_a_failed_baseline_is_reported_and_the_next_archive_is_still_acquired(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cordon_scanner.intel.registries.registry_client import RegistryError

        self._world(monkeypatch, ("pypi", "pkg", "2.0"), baseline_error=RegistryError("timeout"))
        second = tmp_path / "second.whl"
        second.write_bytes(b"x")
        code = self._run(tmp_path, targets=[str(second), str(tmp_path / "missing.whl")])
        assert code == int(ExitCode.SCANNER_ERROR)
        lines = capsys.readouterr().out.splitlines()
        assert lines[0].endswith("second.whl: could not acquire: timeout")
        assert "missing.whl: could not acquire:" in lines[1]

    def test_what_is_not_a_release_history_can_compare_is_skipped_without_failing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._world(monkeypatch, None)
        assert self._run(tmp_path) == int(ExitCode.CLEAN)
        assert "skipped, not a release this can compare" in capsys.readouterr().out
        self._world(monkeypatch, ("npm", "pkg", "1"), release_ecosystems=("pypi",))
        assert self._run(tmp_path) == int(ExitCode.CLEAN)
        assert "skipped, not a release this can compare" in capsys.readouterr().out

    def test_json_output_lists_every_target_with_its_baseline_facts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._world(monkeypatch, ("pypi", "pkg", "2.0"), baseline=self._baseline())
        assert self._run(tmp_path, json_=True) == int(ExitCode.CLEAN)
        (row,) = json.loads(capsys.readouterr().out)
        assert row["release"] == "pkg@2.0" and row["baseline"] == "1.0" and row["files"] == 3
        assert row["baseline_published"] == "2025-01-02T03:04:05Z"

    def test_acquire_is_refused_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(feed.FeedClient, "offline_requested", staticmethod(lambda: True))
        with pytest.raises(ConfigError, match="release history will not be fetched"):
            self._run(tmp_path)
