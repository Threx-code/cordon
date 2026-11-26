"""The release a package is compared with (`--online`): the one before it on its own line, not the
latest published before it. `scan pkg:npm/express@4.21.2 --online` compared 4.21.2 with 5.0.1,
because 5.0.1 was published first: maintained release lines interleave in time."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cordon_scanner.intel.registries.registry_client import RegistryClient
from cordon_scanner.intel.registries.registry_request import RegistryRequest
from cordon_scanner.sources.previous import Identity, PreviousRelease

BLOB = b"a release"
SHA512 = "sha512-" + base64.b64encode(hashlib.sha512(BLOB).digest()).decode()


class Registry:
    """Substitutes the documents a registry serves and the bytes of its archives."""

    @staticmethod
    def serve(monkeypatch: Any, documents: dict[str, dict[str, Any]]) -> list[str]:
        asked: list[str] = []

        def fetch(url: str, **_kwargs: Any) -> dict[str, Any]:
            asked.append(url)
            return documents[url]

        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(fetch))
        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(lambda url, allow, **k: BLOB))
        return asked


class TestTheReleaseBefore:
    def test_npm_takes_the_release_before_on_its_own_line(self, tmp_path, monkeypatch) -> None:
        packument = {
            "name": "express",
            "time": {
                "4.21.1": "2024-10-08T00:00:00Z",
                "5.0.1": "2024-10-09T00:00:00Z",
                "4.21.2": "2024-12-05T00:00:00Z",
                "5.1.0": "2025-03-31T00:00:00Z",
            },
            "versions": {v: {} for v in ("4.21.1", "5.0.1", "4.21.2", "5.1.0")},
        }
        documents = {"https://registry.npmjs.org/express": packument}
        for v in packument["versions"]:
            documents[f"https://registry.npmjs.org/express/{v}"] = {
                "version": v,
                "dist": {"tarball": f"https://registry.npmjs.org/express/-/express-{v}.tgz", "integrity": SHA512},
            }
        Registry.serve(monkeypatch, documents)

        found = PreviousRelease.fetch_previous(Identity("npm", "express", "4.21.2"), tmp_path)

        assert found is not None and found.label == "express 4.21.1"

    def test_pypi_takes_the_release_before_on_its_own_line(self, tmp_path, monkeypatch) -> None:
        def files(v: str, when: str) -> list[dict[str, Any]]:
            return [
                {
                    "upload_time_iso_8601": when,
                    "packagetype": "sdist",
                    "url": f"https://files.pythonhosted.org/demo-{v}.tar.gz",
                    "filename": f"demo-{v}.tar.gz",
                    "digests": {"sha256": hashlib.sha256(BLOB).hexdigest()},
                }
            ]

        releases = {
            "1.2.3": files("1.2.3", "2024-01-01T00:00:00Z"),
            "2.0.0": files("2.0.0", "2024-02-01T00:00:00Z"),
            "1.2.4": files("1.2.4", "2024-03-01T00:00:00Z"),
        }
        documents = {"https://pypi.org/pypi/demo/json": {"info": {"name": "demo"}, "releases": releases}}
        for v, found in releases.items():
            documents[f"https://pypi.org/pypi/demo/{v}/json"] = {"urls": found}
        Registry.serve(monkeypatch, documents)

        found = PreviousRelease.fetch_previous(Identity("pypi", "demo", "1.2.4"), tmp_path)

        assert found is not None and found.label == "demo 1.2.3"

    def test_an_archive_that_does_not_match_its_digest_is_an_error_not_a_comparison(self, tmp_path, monkeypatch) -> None:
        import pytest

        packument = {
            "name": "demo",
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "1.1.0": "2024-02-01T00:00:00Z"},
            "versions": {"1.0.0": {}, "1.1.0": {}},
        }
        documents = {"https://registry.npmjs.org/demo": packument}
        for v in ("1.0.0", "1.1.0"):
            documents[f"https://registry.npmjs.org/demo/{v}"] = {
                "version": v,
                "dist": {"tarball": f"https://registry.npmjs.org/demo/-/demo-{v}.tgz", "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode()},
            }
        Registry.serve(monkeypatch, documents)
        with pytest.raises(ValueError, match="does not match"):
            PreviousRelease.fetch_previous(Identity("npm", "demo", "1.1.0"), tmp_path)
