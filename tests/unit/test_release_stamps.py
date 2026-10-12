"""Everything that names a release names the package's: the MCP Registry entry and the JetBrains
plugin are bumped with `version.py` or the release says two things (the VS Code extension's own
test holds its manifest to the same)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cordon_scanner.version import __version__

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "server.json"
PLUGIN = ROOT / "editors" / "jetbrains" / "build.gradle.kts"


@pytest.mark.skipif(not SERVER.exists(), reason="server.json is not shipped in the sdist")
class TestTheRegistryEntry:
    def test_the_entry_and_its_package_name_the_package_version(self) -> None:
        entry = json.loads(SERVER.read_text(encoding="utf-8"))
        assert entry["version"] == __version__
        assert [p["version"] for p in entry["packages"]] == [__version__] * len(entry["packages"])


@pytest.mark.skipif(not PLUGIN.exists(), reason="editors/ is not shipped in the sdist")
class TestTheJetBrainsPlugin:
    def test_the_plugin_names_the_package_version(self) -> None:
        found = re.search(
            r'^version = "([^"]+)"$', PLUGIN.read_text(encoding="utf-8"), re.MULTILINE
        )
        assert found is not None and found.group(1) == __version__
