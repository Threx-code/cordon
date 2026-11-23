"""The scan upload carries each dependency's lockfile integrity hash, so the platform can give a lockfile occurrence a real digest."""

from __future__ import annotations

import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.cloud.results import SignedResults
from cordon_scanner.foundation.config.settings import Config

NPM_HASH = "sha512-" + "A" * 86 + "=="
PIP_HASH = "sha256:" + "ab" * 32


class Project:
    @staticmethod
    def write(root: Path) -> None:
        (root / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}),
            encoding="utf-8",
        )
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "demo",
                            "version": "1.0.0",
                            "dependencies": {"left-pad": "1.3.0"},
                        },
                        "node_modules/left-pad": {
                            "version": "1.3.0",
                            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                            "integrity": NPM_HASH,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (root / "requirements.txt").write_text(
            f"requests==2.31.0 \\\n    --hash={PIP_HASH}\n", encoding="utf-8"
        )

    @staticmethod
    def uploaded(root: Path) -> list[dict]:
        Project.write(root)
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)
        return json.loads(SignedResults.results_bytes(result))["dependencies"]


class TestTheUploadCarriesIntegrity:
    def test_an_npm_lockfile_dependency_carries_its_integrity(self, tmp_path: Path) -> None:
        deps = {d["name"]: d for d in Project.uploaded(tmp_path)}
        assert deps["left-pad"]["integrity"] == NPM_HASH

    def test_a_pip_requirement_with_a_hash_carries_it(self, tmp_path: Path) -> None:
        deps = {d["name"]: d for d in Project.uploaded(tmp_path)}
        assert deps["requests"]["integrity"].endswith("ab" * 32)
