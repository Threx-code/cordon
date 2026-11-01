"""The package metadata committed under src/ is what the build backend makes from pyproject.toml.

The tree commits `src/cordon_scanner-*.dist-info/` so a checkout on PYTHONPATH has its entry points.
A new entry point added to pyproject.toml alone left the committed copy without it, and whatever put
src first on sys.path then hid the new built-in: "1 built-in detector(s) could not be loaded" across
115 unrelated tests (item 54). This fails on the change that forgets it, naming the difference."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from support import ROOT


class MetadataKit:
    @staticmethod
    def backend():
        spec = importlib.util.spec_from_file_location(
            "cordon_build", ROOT / "scripts" / "backend" / "cordon_build.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class TestTheCommittedMetadata:
    @pytest.mark.parametrize("name", ["entry_points.txt", "top_level.txt"])
    def test_it_is_what_the_backend_generates(self, tmp_path, name: str) -> None:
        committed = sorted((ROOT / "src").glob("cordon_scanner-*.dist-info"))
        assert len(committed) == 1, committed
        backend = MetadataKit.backend()
        before = Path.cwd()
        os.chdir(ROOT)
        try:
            made = backend.prepare_metadata_for_build_wheel(str(tmp_path))
        finally:
            os.chdir(before)
        generated = (tmp_path / made / name).read_text(encoding="utf-8")
        assert (committed[0] / name).read_text(encoding="utf-8") == generated, (
            f"src/{committed[0].name}/{name} differs from what pyproject.toml makes: regenerate it "
            "with scripts/backend/cordon_build.py"
        )
