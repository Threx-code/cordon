"""`OneOff.cache`: a once-per-process loader, cached like `functools.cache`, and no per-file time
budget for it to be charged to. A two-line `.mcp.json` once came back incomplete on a loaded machine
because compiling the agent threat catalogue was charged to it; since 2026-10-31 no file is cut on
the clock, so the loader keeps no clock either."""

from __future__ import annotations

import json
import time
from typing import ClassVar

from cordon_scanner.foundation.once import OneOff


class TestTheLoader:
    def test_a_first_call_loads_and_a_second_is_cached(self) -> None:
        calls = []

        @OneOff.cache
        def load() -> int:
            calls.append(1)
            return 7

        assert load() == 7 and load() == 7
        assert calls == [1]

    def test_clearing_makes_the_next_call_a_load_again(self) -> None:
        calls = []

        @OneOff.cache
        def load() -> int:
            calls.append(1)
            return 1

        load()
        load.cache_clear()
        load()
        assert calls == [1, 1]

    def test_the_loader_keeps_no_clock(self) -> None:
        """Nothing reads a one-off load's time since the per-file cut went: none is kept."""
        assert not hasattr(OneOff, "spent")


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

    def test_the_file_s_own_time_cuts_nothing(self, tmp_path, monkeypatch) -> None:
        """No per-file wall-clock cut (2026-10-31): a file whose own work outruns per_file_timeout
        is read to its end, with the findings a quick run gives, and the scan stays complete."""
        from cordon_scanner.intel.malware.atr import AtrEngine

        real = AtrEngine.catalogue

        def slow():
            time.sleep(1.0)
            return real()

        quick = self._scan(tmp_path, monkeypatch, real)
        result = self._scan(tmp_path, monkeypatch, slow)
        assert "OPERATIONAL.FILE.TIMEOUT" not in {f.rule_id for f in result.findings}
        assert result.complete == quick.complete
        assert sorted(f.rule_id for f in result.findings) == sorted(
            f.rule_id for f in quick.findings
        )
