"""What each ecosystem records so that a package's upstream can be named exactly.

- conda: the artifact's own URL on the public channels, which names its channel (conda-forge's and
  main's builds of one version are different packages); the URL was dropped.
- Bazel: `bazel_tools@_` and `local_config_platform@_` are built into Bazel: platform, not packages.
- vcpkg: a port pinned by an override still comes from the version database at the baseline, which
  its note now names.
"""

from __future__ import annotations

import json

from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.registry import EcosystemRegistry


class TestRecords:
    @staticmethod
    def ecosystem(name: str):
        found = EcosystemRegistry.get(name)
        assert found is not None
        return found

    def test_a_conda_artifact_keeps_its_url(self) -> None:
        url = "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.1-hb9d3cd8_2.conda"
        text = f"@EXPLICIT\n{url}#{'a' * 32}\n"
        graph = self.ecosystem("conda").parse_lockfile(
            FileContent.from_bytes("explicit-linux.txt", text.encode())
        )
        (entry,) = graph.entries
        assert entry.resolved_from == url

    def test_bazels_built_in_modules_are_platform(self) -> None:
        lock = {
            "lockFileVersion": 3,
            "moduleDepGraph": {
                "<root>": {"name": "app", "version": "", "deps": {"zlib": "zlib@1.3.1"}},
                "zlib@1.3.1": {"name": "zlib", "version": "1.3.1", "deps": {}},
                "bazel_tools@_": {"name": "bazel_tools", "version": "_", "deps": {}},
            },
        }
        graph = self.ecosystem("bazel").parse_lockfile(
            FileContent.from_bytes("MODULE.bazel.lock", json.dumps(lock).encode())
        )
        by_name = {e.name: e for e in graph.entries}
        assert by_name["bazel_tools"].bundled and by_name["bazel_tools"].scope is Scope.PLATFORM
        assert not by_name["zlib"].bundled

    def test_a_pinned_vcpkg_port_names_its_baseline(self) -> None:
        baseline = "4b308f5ccd45aed57f2977257bca304dfef43c99"
        manifest = {
            "name": "app",
            "builtin-baseline": baseline,
            "dependencies": ["fmt", "zlib"],
            "overrides": [{"name": "fmt", "version": "10.2.1"}],
        }
        parsed = self.ecosystem("vcpkg").parse_manifest(
            FileContent.from_bytes("vcpkg.json", json.dumps(manifest).encode())
        )
        notes = {d.name: d.note for d in parsed.dependencies}
        assert notes["fmt"] == f"pinned by an override; vcpkg reads the port at baseline {baseline}"
        assert notes["zlib"] and f"at baseline {baseline}" in notes["zlib"]
