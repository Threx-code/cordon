"""A version made to win resolution, an install hook running its own script, and no other code."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.manifests.detector import CONFUSION_RULE, ManifestDetector
from cordon_scanner.foundation.config.settings import Config


class ConfusionKit:
    @staticmethod
    def package(
        root: Path, *, version: str = "99.99.99", scripts=None, files=("index.js",)
    ) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        manifest = {"name": "internal-design-system", "version": version, "main": "index.js"}
        manifest["scripts"] = {"preinstall": "node preinstall.js"} if scripts is None else scripts
        (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (root / "preinstall.js").write_text("console.log('installed')\n", encoding="utf-8")
        for name in files:
            (root / name).write_text("module.exports = {};\n", encoding="utf-8")
        return root

    @staticmethod
    def rules(root: Path) -> set[str]:
        config = Config.default().with_overrides(use_cache=False)
        return {
            f.rule_id for f in Scanner(config, detectors=(ManifestDetector(),)).scan(root).findings
        }


class TestDependencyConfusion:
    @pytest.mark.parametrize("version", ["99.99.99", "99.0.2", "9.9.9", "100.0.0"])
    def test_the_shape_is_reported(self, tmp_path, version) -> None:
        assert CONFUSION_RULE in ConfusionKit.rules(
            ConfusionKit.package(tmp_path / "p", version=version)
        )

    @pytest.mark.parametrize("version", ["1.2.3", "9.9.8", "98.0.0", "0.0.1"])
    def test_an_ordinary_version_is_not(self, tmp_path, version) -> None:
        assert CONFUSION_RULE not in ConfusionKit.rules(
            ConfusionKit.package(tmp_path / "p", version=version)
        )

    def test_a_build_step_is_not(self, tmp_path) -> None:
        root = ConfusionKit.package(tmp_path / "p", scripts={"install": "node-gyp rebuild"})
        assert CONFUSION_RULE not in ConfusionKit.rules(root)

    def test_a_package_with_code_of_its_own_is_not(self, tmp_path) -> None:
        root = ConfusionKit.package(tmp_path / "p")
        (root / "lib").mkdir(exist_ok=True)
        for name in ("a.js", "b.js"):
            (root / "lib" / name).write_text("module.exports = 1;\n", encoding="utf-8")
        assert CONFUSION_RULE not in ConfusionKit.rules(root)

    def test_no_install_hook_is_not(self, tmp_path) -> None:
        root = ConfusionKit.package(tmp_path / "p", scripts={"test": "node test.js"})
        assert CONFUSION_RULE not in ConfusionKit.rules(root)
