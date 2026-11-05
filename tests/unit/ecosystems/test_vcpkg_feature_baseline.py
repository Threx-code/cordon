"""A port under an optional feature, or pinned by an override inside one, is still resolved at the
manifest's baseline: the note that says why it is optional keeps the baseline too."""

from __future__ import annotations

import json

from cordon_scanner.ecosystems.packages.vcpkg import VcpkgEcosystem
from cordon_scanner.foundation.content import FileContent

BASELINE = "e6e4bc74aaf5c63dfc358810594f662f7e9bc4d4"


class TestFeatureBaseline:
    def test_a_feature_dependency_and_its_override_keep_the_baseline(self) -> None:
        manifest = {
            "name": "x",
            "builtin-baseline": BASELINE,
            "features": {
                "tests": {
                    "description": "t",
                    "dependencies": ["catch2", {"name": "sophus", "version>=": "1.22.10"}],
                }
            },
            "overrides": [{"name": "sophus", "version": "1.22.10"}],
        }
        parsed = VcpkgEcosystem().parse_manifest(
            FileContent.from_bytes("vcpkg.json", json.dumps(manifest).encode())
        )
        notes = {d.name: d.note or "" for d in parsed.dependencies}
        assert (
            "optional feature `tests`" in notes["catch2"]
            and f"at baseline {BASELINE}" in notes["catch2"]
        )
        assert f"at baseline {BASELINE}" in notes["sophus"]
