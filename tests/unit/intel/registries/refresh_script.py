"""The package-intel refresh script, loaded as a module for the tests that read its tables and run its fetchers."""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType

from support import ROOT

SCRIPT = ROOT / "scripts" / "refresh" / "refresh_package_intel.py"
NAME = "refresh_package_intel_under_test"


def refresh_module() -> ModuleType:
    """The script as a module (it finds the repository from the working directory, so callers `chdir` first)."""
    if NAME in sys.modules:
        return sys.modules[NAME]
    spec = importlib.util.spec_from_file_location(NAME, SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[NAME] = module
    spec.loader.exec_module(module)
    return module
