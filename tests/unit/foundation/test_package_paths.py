"""The scanner finds its own data from the package, not from module depth (`core/paths.py`).

A module moved into a subfolder (reviews 20-PACKAGE-STRUCTURE.md) must still find what it ships
with: each path below exists, wherever the module that names it lives.
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path
from typing import ClassVar

import cordon_scanner
from cordon_scanner.decide import intent, verdict
from cordon_scanner.detect.agents.mcp_servers import description_model
from cordon_scanner.detect.binary import binary_imports, rule_files
from cordon_scanner.detect.infra import iac_policies
from cordon_scanner.engine import registry
from cordon_scanner.foundation.paths import PackagePaths
from cordon_scanner.intel.advisories import advisories
from cordon_scanner.intel.malware import feed
from cordon_scanner.intel.registries import real
from cordon_scanner.intel.store import dbsync
from support import ROOT as REPO

PACKAGE = Path(cordon_scanner.__file__).resolve().parent


class TestPackagePaths:
    def test_the_root_is_the_package(self) -> None:
        assert PackagePaths.root() == PACKAGE
        assert registry._PACKAGE_ROOT == PACKAGE

    def test_every_bundled_path_exists(self) -> None:
        files = [
            description_model.MODEL_PATH,
            description_model.SKILL_MODEL_PATH,
            intent.MODEL_PATH,
            rule_files.BUILTIN_PACK,
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

    #: Not loaded at run time, so not in the wheel: the third-party rules the built-in rule pack is
    #: assembled from, shipped in the sdist with their licence record (MANIFEST.in).
    NOT_IN_WHEEL: ClassVar[tuple[str, ...]] = ("rules/rule_files/upstream/",)

    def test_every_bundled_file_is_declared_for_the_wheel(self) -> None:
        """Every data file in the package must match pyproject's package-data, or an install from
        PyPI runs without it, quietly: until 2026-10-20 the wheel lacked the rule pack and the
        bundled EPSS scores (`intel/data/epss.csv.gz`)."""
        declared = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        globs = [
            PACKAGE.joinpath(*package.split(".")[1:]) / pattern
            for package, patterns in declared["tool"]["cordon-build"]["package-data"].items()
            for pattern in patterns
        ]
        data = [
            p
            for p in sorted(PACKAGE.rglob("*"))
            if p.is_file()
            and p.suffix not in (".py", ".pyc")
            and "__pycache__" not in p.parts
            and not p.relative_to(PACKAGE).as_posix().startswith(self.NOT_IN_WHEEL)
        ]
        assert len(data) > 50  # a walk that found nothing passes for the wrong reason
        missing = [
            p.relative_to(PACKAGE).as_posix()
            for p in data
            if not any(fnmatch.fnmatch(str(p), str(g)) for g in globs)
        ]
        assert not missing, f"declare these in pyproject package-data: {missing}"

    def test_the_same_paths_as_before_the_anchor(self) -> None:
        assert intent.MODEL_PATH == PACKAGE / "detect" / "data" / "intent.json.gz"
        assert (
            description_model.MODEL_PATH == PACKAGE / "detect" / "data" / "mcp-descriptions.json.gz"
        )
        assert real.DATA_DIR == PACKAGE / "intel" / "data"
        assert advisories.DATA_DIR == PACKAGE / "intel" / "data"
        assert iac_policies.DATA_DIR == PACKAGE / "detect" / "data"
