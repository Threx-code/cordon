"""The scanner finds its own data from the package, not from module depth (`core/paths.py`).

A module moved into a subfolder (reviews 20-PACKAGE-STRUCTURE.md) must still find what it ships
with: each path below exists, wherever the module that names it lives.
"""

from __future__ import annotations

from pathlib import Path

import cordon_scanner
from cordon_scanner.decide import intent, verdict
from cordon_scanner.detect.agents import mcp_model
from cordon_scanner.detect.binary import binary_imports, yara_rules
from cordon_scanner.detect.infra import iac_policies
from cordon_scanner.engine import registry
from cordon_scanner.foundation.paths import PackagePaths
from cordon_scanner.intel.advisories import advisories
from cordon_scanner.intel.malware import feed
from cordon_scanner.intel.registries import real
from cordon_scanner.intel.store import dbsync

PACKAGE = Path(cordon_scanner.__file__).resolve().parent


class TestPackagePaths:
    def test_the_root_is_the_package(self) -> None:
        assert PackagePaths.root() == PACKAGE
        assert registry._PACKAGE_ROOT == PACKAGE

    def test_every_bundled_path_exists(self) -> None:
        files = [
            mcp_model.MODEL_PATH,
            mcp_model.SKILL_MODEL_PATH,
            intent.MODEL_PATH,
            yara_rules.BUILTIN_PACK,
        ]
        for path in files:
            assert path.is_file(), path
        folders = [
            iac_policies.DATA_DIR,
            binary_imports.ImportCapabilities.DATA,
            real.DATA_DIR,
            advisories.DATA_DIR,
        ]
        for folder in folders:
            assert folder.is_dir(), folder
        # Shipped only with a trained model, and with the feed's key ceremony: their directories.
        assert verdict.MODEL_PATH.parent == PACKAGE / "detect" / "data"
        assert feed.ROOT_FILE.parent == PACKAGE / "intel" / "data"
        assert dbsync.PUBLIC_KEY_FILE.parent == PACKAGE / "intel" / "data"

    def test_the_same_paths_as_before_the_anchor(self) -> None:
        assert intent.MODEL_PATH == PACKAGE / "detect" / "data" / "intent.json.gz"
        assert mcp_model.MODEL_PATH == PACKAGE / "detect" / "data" / "mcp-descriptions.json.gz"
        assert real.DATA_DIR == PACKAGE / "intel" / "data"
        assert advisories.DATA_DIR == PACKAGE / "intel" / "data"
        assert iac_policies.DATA_DIR == PACKAGE / "detect" / "data"
