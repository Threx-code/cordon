"""The release a package is compared with (`--online`): the one before it on its own line, not the
latest published before it. `scan pkg:npm/express@4.21.2 --online` compared 4.21.2 with 5.0.1,
because 5.0.1 was published first: maintained release lines interleave in time."""

from __future__ import annotations

import base64
import hashlib

from cordon_scanner.sources.previous import Identity, PreviousRelease

BLOB = b"a release"
SHA512 = "sha512-" + base64.b64encode(hashlib.sha512(BLOB).digest()).decode()


class TestTheReleaseBefore:
    def test_npm_takes_the_release_before_on_its_own_line(self, tmp_path, monkeypatch) -> None:
        def version(v):
            return {"dist": {"tarball": f"https://registry.invalid/{v}.tgz", "integrity": SHA512}}

        document = {
            "time": {
                "4.21.1": "2024-10-08T00:00:00Z",
                "5.0.1": "2024-10-09T00:00:00Z",
                "4.21.2": "2024-12-05T00:00:00Z",
                "5.1.0": "2025-03-31T00:00:00Z",
            },
            "versions": {v: version(v) for v in ("4.21.1", "5.0.1", "4.21.2", "5.1.0")},
        }
        monkeypatch.setattr(PreviousRelease, "_document", staticmethod(lambda url: document))
        monkeypatch.setattr(PreviousRelease, "_artefact", staticmethod(lambda url, eco: BLOB))

        found = PreviousRelease.fetch_previous(Identity("npm", "express", "4.21.2"), tmp_path)

        assert found is not None and found.label == "express 4.21.1"

    def test_pypi_takes_the_release_before_on_its_own_line(self, tmp_path, monkeypatch) -> None:
        def files(v, when):
            return [
                {
                    "upload_time_iso_8601": when,
                    "packagetype": "sdist",
                    "url": f"https://files.invalid/demo-{v}.tar.gz",
                    "filename": f"demo-{v}.tar.gz",
                    "digests": {"sha256": hashlib.sha256(BLOB).hexdigest()},
                }
            ]

        document = {
            "releases": {
                "1.2.3": files("1.2.3", "2024-01-01T00:00:00Z"),
                "2.0.0": files("2.0.0", "2024-02-01T00:00:00Z"),
                "1.2.4": files("1.2.4", "2024-03-01T00:00:00Z"),
            }
        }
        monkeypatch.setattr(PreviousRelease, "_document", staticmethod(lambda url: document))
        monkeypatch.setattr(PreviousRelease, "_artefact", staticmethod(lambda url, eco: BLOB))

        found = PreviousRelease.fetch_previous(Identity("pypi", "demo", "1.2.4"), tmp_path)

        assert found is not None and found.label == "demo 1.2.3"
