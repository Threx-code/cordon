"""decide.verdict_features from the workers' facts (item 56, phase (a)): the parent reads no source
bytes for the package verdict, and the verdict is identical to the one read from the bytes. The
feature record key for key, the vector the model reads (built from it in the model's own order) and
the score exactly: in every scan here, both are computed and compared."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner import Config, Scanner
from cordon_scanner.decide.verdict_features import VerdictFeatures
from cordon_scanner.engine.pipeline.ceilings import Ceilings
from support import ROOT

MALICIOUS = ROOT / "corpus" / "malicious"


class Twice:
    """Ceilings.verdict computed from the facts and again from the bytes, in the same scan."""

    compared: ClassVar[list[str]] = []

    @staticmethod
    def install(monkeypatch) -> None:
        real = Ceilings.verdict
        Twice.compared = []

        def both(findings, units, profile=None, intent=None, *, repository=False, facts=None):
            from_facts = real(
                list(findings), units, profile, intent, repository=repository, facts=facts
            )
            from_bytes = real(
                list(findings), units, profile, intent, repository=repository, facts=None
            )
            assert facts is not None, "the pipeline gave the verdict no facts"
            assert from_facts[1] == from_bytes[1], (
                "the verdict summary differs: features, vector or score"
            )
            assert [f.to_dict() for f in from_facts[0]] == [f.to_dict() for f in from_bytes[0]]
            Twice.compared.append(str(from_facts[1].get("score")))
            return from_facts

        monkeypatch.setattr(Ceilings, "verdict", staticmethod(both))

    @staticmethod
    def scan(target):
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(target)

    @staticmethod
    def package(tmp_path: Path, files: dict[str, str]) -> Path:
        target = tmp_path / "p-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return target


class TestTheSourceFactsAreTheBytes:
    def test_one_function_reads_both(self) -> None:
        data = (
            b"const a = require('left-pad'); fetch('https://x.invalid'); require('child_process')"
        )
        named, shows = VerdictFeatures.source_facts(data, frozenset({"left-pad", "unused"}))
        assert named == {"left-pad"} and "network" in shows


class TestTheVerdictIsIdentical:
    @pytest.mark.parametrize(
        "sample", sorted(p for p in MALICIOUS.iterdir() if p.is_dir()), ids=lambda p: p.name
    )
    def test_on_every_malicious_corpus_sample(self, sample, monkeypatch) -> None:
        Twice.install(monkeypatch)
        Twice.scan(sample)
        assert Twice.compared

    def test_a_package_that_names_some_of_its_dependencies(self, tmp_path, monkeypatch) -> None:
        Twice.install(monkeypatch)
        manifest = {
            "name": "p",
            "version": "1.0.0",
            "dependencies": {"left-pad": "1", "is-odd": "1"},
        }
        Twice.scan(
            Twice.package(
                tmp_path,
                {
                    "package.json": json.dumps(manifest),
                    "index.js": "module.exports = require('left-pad');\n",
                },
            )
        )
        assert Twice.compared

    def test_with_a_lifted_unit(self, tmp_path, monkeypatch) -> None:
        from unit.analysis.shared.test_deobfuscation import ObfuscatedKit

        Twice.install(monkeypatch)
        body = ObfuscatedKit.program(
            body="require('child_process').execSync(process.env.HOME_CMD);"
        )
        manifest = {"name": "p", "version": "1.0.0", "scripts": {"postinstall": "node index.js"}}
        Twice.scan(
            Twice.package(tmp_path, {"package.json": json.dumps(manifest), "index.js": body})
        )
        assert Twice.compared

    def test_where_the_400_source_cap_binds(self, tmp_path, monkeypatch) -> None:
        """The one place the units' order changes a value: _ability reads the first 400 sources."""
        Twice.install(monkeypatch)
        files = {"package.json": json.dumps({"name": "p", "version": "1.0.0"})}
        files.update({f"lib/m{i:03d}.js": f"module.exports = {i};\n" for i in range(405)})
        files["lib/m404.js"] = "require('child_process').exec(process.argv[2]);\n"  # past the cap
        Twice.scan(Twice.package(tmp_path, files))
        assert Twice.compared

    @pytest.mark.parametrize("shallow", ["{ not json", "[1, 2, 3]"], ids=["unparseable", "a-list"])
    def test_when_the_shallowest_manifest_does_not_parse(
        self, tmp_path, monkeypatch, shallow
    ) -> None:
        """wanted_dependencies passes it by as the verdict's own loop does, so both read the deeper
        one (modelling team's review of 1445a5c5)."""
        Twice.install(monkeypatch)
        deeper = {"name": "inner", "version": "1.0.0", "dependencies": {"left-pad": "1"}}
        Twice.scan(
            Twice.package(
                tmp_path,
                {
                    "package.json": shallow,
                    "lib/package.json": json.dumps(deeper),
                    "lib/index.js": "require('left-pad');\n",
                },
            )
        )
        assert Twice.compared

    @pytest.mark.parametrize("deps", [["left-pad"], "left-pad"], ids=["a-list", "a-string"])
    def test_when_dependencies_is_not_a_mapping(self, tmp_path, monkeypatch, deps) -> None:
        Twice.install(monkeypatch)
        manifest = {"name": "p", "version": "1.0.0", "dependencies": deps}
        Twice.scan(
            Twice.package(
                tmp_path,
                {"package.json": json.dumps(manifest), "index.js": "require('left-pad');\n"},
            )
        )
        assert Twice.compared
