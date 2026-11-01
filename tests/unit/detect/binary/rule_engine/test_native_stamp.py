"""A native anchor module from another build is not used: it falls back to the Python matcher with
the reason said, never loading and then raising mid-scan (item 17; design note 17-native-stamp.md).
Before, `Native.load` took any importable `_anchors`, so a stale build without `text_hits`, or with
another interface, was loaded and failed on its first call."""

from __future__ import annotations

import sys
import types

from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Native


class StampKit:
    @staticmethod
    def stub(monkeypatch, *, abi: int | None, drop: tuple[str, ...] = ()) -> None:
        module = types.ModuleType("cordon_scanner._native._anchors")
        automaton = type(
            "Automaton", (), {"present": lambda self, data: (), "positions": lambda self, *a: ()}
        )
        for name, value in (
            ("Automaton", automaton),
            ("check_text", lambda *a: b""),
            ("text_hits", lambda *a: ((), ())),
            ("hex_hits", lambda *a: ((), ())),
        ):
            if name not in drop:
                setattr(module, name, value)
        if abi is not None:
            module.ABI = abi
        monkeypatch.setitem(sys.modules, "cordon_scanner._native._anchors", module)
        monkeypatch.delenv("CORDON_NO_NATIVE", raising=False)


class TestAModuleFromAnotherBuildIsNotUsed:
    def test_one_with_no_stamp_falls_back(self, monkeypatch) -> None:
        StampKit.stub(monkeypatch, abi=None)
        module, why = Native.load()
        assert module is None
        assert "another build" in why

    def test_one_with_another_stamp_falls_back(self, monkeypatch) -> None:
        StampKit.stub(monkeypatch, abi=Native.ABI + 1)
        module, why = Native.load()
        assert module is None
        assert f"expected {Native.ABI}" in why

    def test_one_missing_a_function_falls_back(self, monkeypatch) -> None:
        StampKit.stub(monkeypatch, abi=Native.ABI, drop=("hex_hits",))
        module, why = Native.load()
        assert module is None
        assert "hex_hits" in why

    def test_one_whose_automaton_lacks_a_method_falls_back(self, monkeypatch) -> None:
        StampKit.stub(monkeypatch, abi=Native.ABI)
        sys.modules["cordon_scanner._native._anchors"].Automaton = type("Automaton", (), {})
        module, why = Native.load()
        assert module is None
        assert "positions" in why or "present" in why

    def test_a_matching_module_is_used(self, monkeypatch) -> None:
        StampKit.stub(monkeypatch, abi=Native.ABI)
        module, why = Native.load()
        assert module is not None
        assert why == "native"


class TestAStaleBuildSaysSo:
    """A fallback is about 9x slower in match time, so a scan says which matcher it used, and a stale
    build's scan says why on stderr, for a pipeline that never runs --version (the outer-layer
    team's review of note 17)."""

    def test_the_report_names_its_matcher(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            tmp_path
        )
        assert "anchor matcher" in result.to_dict()["matcher"]

    def test_a_stale_build_warns_once_per_scan(self, monkeypatch, capsys) -> None:
        from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton
        from cordon_scanner.engine.engine import Engine

        monkeypatch.setattr(Automaton, "MODULE", None)
        monkeypatch.setattr(
            Automaton, "WHY", "the native anchor matcher is from another build (ABI 0, expected 1)"
        )
        Engine.say_a_stale_matcher()
        assert capsys.readouterr().err.count("another build") == 1

    def test_a_build_not_made_says_nothing(self, monkeypatch, capsys) -> None:
        from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton
        from cordon_scanner.engine.engine import Engine

        monkeypatch.setattr(Automaton, "MODULE", None)
        monkeypatch.setattr(Automaton, "WHY", "the native anchor matcher is not built (no module)")
        Engine.say_a_stale_matcher()
        assert capsys.readouterr().err == ""
