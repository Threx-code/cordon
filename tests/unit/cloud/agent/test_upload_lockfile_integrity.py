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


class TestEveryListedHashReachesThePlatform:
    """A package listed with a hash per wheel carries all of them (`hashes`), and `integrity` stays the first."""

    A, B, C = ("sha256:" + c * 64 for c in "abc")

    @staticmethod
    def uploaded(root: Path, files: dict[str, str]) -> dict[str, dict]:
        for name, text in files.items():
            (root / name).write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)
        return {
            d["name"]: d for d in json.loads(SignedResults.results_bytes(result))["dependencies"]
        }

    def test_a_requirements_entry_with_three_hashes(self, tmp_path: Path) -> None:
        text = f"requests==2.31.0 \\\n    --hash={self.A} \\\n    --hash={self.B} \\\n    --hash={self.C}\n"
        dep = self.uploaded(tmp_path, {"requirements.txt": text})["requests"]
        assert dep["hashes"] == [self.A, self.B, self.C] and dep["integrity"] == self.A

    def test_a_poetry_entry_with_three_files(self, tmp_path: Path) -> None:
        lock = (
            '[[package]]\nname = "requests"\nversion = "2.31.0"\ndescription = ""\noptional = false\npython-versions = ">=3.7"\n'
            f'files = [\n    {{file = "a.whl", hash = "{self.A}"}},\n    {{file = "b.whl", hash = "{self.B}"}},\n'
            f'    {{file = "c.tar.gz", hash = "{self.C}"}},\n]\n\n[metadata]\nlock-version = "2.0"\npython-versions = "^3.8"\ncontent-hash = "x"\n'
        )
        project = '[tool.poetry]\nname = "demo"\nversion = "1.0.0"\n[tool.poetry.dependencies]\npython = "^3.8"\nrequests = "2.31.0"\n'
        dep = self.uploaded(tmp_path, {"poetry.lock": lock, "pyproject.toml": project})["requests"]
        assert dep["hashes"] == [self.A, self.B, self.C] and dep["integrity"] == self.A

    def test_a_uv_entry_with_an_sdist_and_two_wheels(self, tmp_path: Path) -> None:
        lock = (
            'version = 1\nrequires-python = ">=3.8"\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            f'sdist = {{ url = "https://example.invalid/r.tar.gz", hash = "{self.A}" }}\n'
            f'wheels = [\n    {{ url = "https://example.invalid/r1.whl", hash = "{self.B}" }},\n'
            f'    {{ url = "https://example.invalid/r2.whl", hash = "{self.C}" }},\n]\n'
        )
        project = '[project]\nname = "demo"\nversion = "1.0.0"\nrequires-python = ">=3.8"\ndependencies = ["requests==2.31.0"]\n'
        dep = self.uploaded(tmp_path, {"uv.lock": lock, "pyproject.toml": project})["requests"]
        assert dep["hashes"] == [self.A, self.B, self.C] and dep["integrity"] == self.A

    def test_an_entry_with_one_hash_lists_it_once(self, tmp_path: Path) -> None:
        text = f"requests==2.31.0 --hash={self.A}\n"
        dep = self.uploaded(tmp_path, {"requirements.txt": text})["requests"]
        assert dep["hashes"] == [self.A] and dep["integrity"] == self.A

    def test_text_that_is_not_a_digest_is_never_listed(self, tmp_path: Path) -> None:
        stray = "ghp_" + "x" * 30
        text = f"requests==2.31.0 --hash={self.A} --hash={stray} --hash=sha256:not-hex\n"
        dep = self.uploaded(tmp_path, {"requirements.txt": text})["requests"]
        assert dep["hashes"] == [self.A] and stray not in json.dumps(dep)
