"""The package-intel refresh script, loaded as a module for the tests that read its tables and run its fetchers."""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType
from typing import ClassVar

from support import ROOT


class RefreshScript:
    SCRIPT: ClassVar = ROOT / "scripts" / "refresh" / "refresh_package_intel.py"
    NAME: ClassVar[str] = "refresh_package_intel_under_test"

    @classmethod
    def module(cls) -> ModuleType:
        """The script as a module (it finds the repository from the working directory, so callers `chdir` first)."""
        if cls.NAME in sys.modules:
            return sys.modules[cls.NAME]
        spec = importlib.util.spec_from_file_location(cls.NAME, cls.SCRIPT)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[cls.NAME] = module
        spec.loader.exec_module(module)
        return module
