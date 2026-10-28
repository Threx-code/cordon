"""`OneOff.cache`: a cached loader whose first call is recorded as the process's cost, and the
per-file budget that leaves that cost out. A two-line `.mcp.json` came back incomplete on a loaded
machine because compiling the agent threat catalogue was charged to it."""

from __future__ import annotations

import json
import time
from typing import ClassVar

from cordon_scanner.foundation.once import OneOff


class TestTheLoader:
    def test_a_first_call_is_recorded_and_a_cached_one_is_not(self) -> None:
        calls = []

        @OneOff.cache
        def load() -> int:
            calls.append(1)
            time.sleep(0.05)
            return 7

        before = OneOff.spent()
        assert load() == 7
        first = OneOff.spent() - before
        assert load() == 7
        assert calls == [1]
        assert first >= 0.05
        assert OneOff.spent() - before == first

    def test_a_load_inside_a_load_is_counted_once(self) -> None:
        @OneOff.cache
        def inner() -> int:
            time.sleep(0.05)
            return 1

        @OneOff.cache
        def outer() -> int:
            time.sleep(0.05)
            return inner() + 1

        before = OneOff.spent()
        started = time.perf_counter()
        assert outer() == 2
        wall = time.perf_counter() - started
        assert OneOff.spent() - before <= wall

    def test_clearing_makes_the_next_call_a_load_again(self) -> None:
        @OneOff.cache
        def load() -> int:
            time.sleep(0.02)
            return 1

        load()
        load.cache_clear()
        before = OneOff.spent()
        load()
        assert OneOff.spent() - before >= 0.02


class TestThePerFileBudget:
    CONFIG: ClassVar[dict[str, object]] = {
        "mcpServers": {"fs": {"command": "npx", "args": ["-y", "some-server"]}}
    }

    def _scan(self, tmp_path, monkeypatch, catalogue):
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config
        from cordon_scanner.intel.malware.atr import AtrEngine

        monkeypatch.setattr(AtrEngine, "catalogue", staticmethod(catalogue))
        (tmp_path / ".mcp.json").write_text(json.dumps(self.CONFIG), encoding="utf-8")
        cfg = Config.default()
        cfg = cfg.with_overrides(use_cache=False, limits=cfg.limits.merged(per_file_timeout=0.5))
        return Scanner(cfg).scan(tmp_path)

    def test_a_first_load_is_not_charged_to_the_file(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.intel.malware.atr import AtrEngine

        real = AtrEngine.catalogue

        @OneOff.cache
        def slow():
            time.sleep(1.0)
            return real()

        result = self._scan(tmp_path, monkeypatch, slow)
        assert "OPERATIONAL.FILE.TIMEOUT" not in {f.rule_id for f in result.findings}
        assert result.complete is True

    def test_the_file_s_own_time_is_still_charged(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.intel.malware.atr import AtrEngine

        real = AtrEngine.catalogue

        def slow():
            time.sleep(1.0)
            return real()

        result = self._scan(tmp_path, monkeypatch, slow)
        assert "OPERATIONAL.FILE.TIMEOUT" in {f.rule_id for f in result.findings}
        assert result.complete is False
