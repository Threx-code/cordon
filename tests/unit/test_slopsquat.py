"""Slopsquatting: documented hallucinated names offline, unregistered names online."""

from __future__ import annotations

import json

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.intel import hallucinated, registry_client
from cordon_scanner.intel.advisories import AdvisoryFiles


class SlopsquatHelpers:
    """Helpers for test_slopsquat.py."""

    @staticmethod
    def _scan(tmp_path, files, **overrides):
        for name, text in files.items():
            (tmp_path / name).write_text(text, encoding="utf-8")
        return Scanner(Config.default().with_overrides(use_cache=False, **overrides)).scan(tmp_path)


class TestTheList:
    def test_a_documented_hallucination_is_found_offline(self, tmp_path) -> None:
        result = SlopsquatHelpers._scan(tmp_path, {"requirements.txt": "Huggingface_CLI==0.1.1\n"})
        [hit] = [f for f in result.findings if f.rule_id == "SUSPECT.DEPENDENCY.HALLUCINATED.001"]
        assert "huggingface_hub[cli]" in hit.message

    def test_a_synced_list_extends_the_bundled_one(self, tmp_path, monkeypatch) -> None:
        sync = tmp_path / "sync"
        sync.mkdir()
        (sync / hallucinated.HALLUCINATED_NAME).write_text(
            json.dumps(
                {
                    "generated": "2999-01-01",
                    "entries": {"npm": {"react-codeshift": {"intended": "jscodeshift"}}},
                }
            ),
            encoding="utf-8",
        )
        from support import SealedSync

        SealedSync.seal(sync)
        monkeypatch.setattr(AdvisoryFiles, "user_sync_dir", lambda: sync)
        hallucinated.HallucinatedPackages.reset_cache()
        try:
            assert (
                hallucinated.HallucinatedPackages.lookup("npm", "react-codeshift").intended
                == "jscodeshift"
            )
        finally:
            hallucinated.HallucinatedPackages.reset_cache()


class TestUnregisteredOnline:
    def test_a_name_the_registry_does_not_have_is_reported(self, tmp_path, monkeypatch) -> None:
        def facts(ecosystem, name, version):
            if name == "invented-helper":
                raise registry_client.PackageNotFound("pypi.org has no package by that name")
            raise registry_client.RegistryError("not asked in this test")

        monkeypatch.setattr(registry_client.RegistryClient, "facts", facts)
        lock = "invented-helper==1.0.0 --hash=sha256:" + "a" * 64 + "\n"
        result = SlopsquatHelpers._scan(tmp_path, {"requirements.txt": lock}, offline=False)
        [hit] = [f for f in result.findings if f.rule_id == "SUSPECT.DEPENDENCY.UNREGISTERED.001"]
        assert "invented-helper" in hit.message

    def test_a_package_resolved_from_a_private_registry_is_not(self, tmp_path, monkeypatch) -> None:
        def facts(ecosystem, name, version):
            raise registry_client.PackageNotFound("registry.npmjs.org has no package by that name")

        monkeypatch.setattr(registry_client.RegistryClient, "facts", facts)
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "app",
                    "version": "1.0.0",
                    "dependencies": {"@acme/internal": "1.0.0"},
                },
                "node_modules/@acme/internal": {
                    "version": "1.0.0",
                    "integrity": "sha512-x",
                    "resolved": "https://npm.acme.internal/@acme/internal/-/internal-1.0.0.tgz",
                },
            },
        }
        files = {
            "package.json": '{"name":"app","version":"1.0.0"}',
            "package-lock.json": json.dumps(lock),
        }
        result = SlopsquatHelpers._scan(tmp_path, files, offline=False)
        assert not [
            f for f in result.findings if f.rule_id == "SUSPECT.DEPENDENCY.UNREGISTERED.001"
        ]


class TestUnvettedOnline:
    def _facts(self, **overrides):
        import datetime as dt

        values = {
            "name": "x",
            "version": "1.0.0",
            "repository": None,
            "first_published": (dt.datetime.now(dt.UTC) - dt.timedelta(days=5)).isoformat(),
            "releases": 1,
            "weekly_downloads": None,
        }
        values.update(overrides)
        return registry_client.PackageFacts(**values)

    def _scan_with(self, tmp_path, monkeypatch, name, facts):
        monkeypatch.setattr(
            registry_client.RegistryClient, "facts", lambda ecosystem, n, version: facts
        )
        lock = f"{name}==1.0.0 --hash=sha256:" + "a" * 64 + "\n"
        return SlopsquatHelpers._scan(tmp_path, {"requirements.txt": lock}, offline=False)

    def test_a_new_sourceless_affixed_name_is_reported(self, tmp_path, monkeypatch) -> None:
        result = self._scan_with(tmp_path, monkeypatch, "requests-helper", self._facts())
        [hit] = [f for f in result.findings if f.rule_id == "SUSPECT.DEPENDENCY.UNVETTED.001"]
        assert "'requests'" in hit.message and "no source repository" in hit.message

    def test_a_repository_or_age_clears_it(self, tmp_path, monkeypatch) -> None:
        for facts in (
            self._facts(repository="https://github.com/a/b"),
            self._facts(first_published="2019-01-01T00:00:00Z"),
        ):
            result = self._scan_with(tmp_path, monkeypatch, "requests-helper", facts)
            assert not [
                f for f in result.findings if f.rule_id == "SUSPECT.DEPENDENCY.UNVETTED.001"
            ]

    def test_an_established_name_is_never_reported(self, tmp_path, monkeypatch) -> None:
        result = self._scan_with(tmp_path, monkeypatch, "requests", self._facts(weekly_downloads=3))
        assert not [f for f in result.findings if f.rule_id == "SUSPECT.DEPENDENCY.UNVETTED.001"]
