"""A component's hash and licence in both SBOM formats, and the reproducible timestamp (`report/sbom.py`)."""

from __future__ import annotations

import pytest

from cordon_scanner.foundation.models import Scope
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.report.sbom import SbomDocument

SHA256 = "ab" * 32


class _Kit:
    @staticmethod
    def dependency(**over: object) -> Dependency:
        fields: dict[str, object] = {
            "purl": "pkg:npm/left-pad@1.3.0",
            "ecosystem": "npm",
            "name": "left-pad",
            "version": "1.3.0",
            "direct": True,
            "scope": Scope.RUNTIME,
            "integrity": f"sha256:{SHA256}",
            "license": "MIT",
        }
        return Dependency(**{**fields, **over})  # type: ignore[arg-type]


class TestComponents:
    def test_a_recorded_digest_and_licence_reach_the_cyclonedx_component(self) -> None:
        document = SbomDocument.cyclonedx_document(
            [_Kit.dependency()],
            root_name="app",
            root_version="1",
            tool_version="x",
            moment="2026-01-01T00:00:00Z",
        )
        [component] = document["components"]
        assert component["hashes"] == [{"alg": "SHA-256", "content": SHA256}]
        assert component["licenses"] == [{"license": {"name": "MIT"}}]

    def test_a_recorded_digest_reaches_the_spdx_package_as_a_checksum(self) -> None:
        document = SbomDocument.spdx_document(
            [_Kit.dependency()],
            root_name="app",
            root_version="1",
            tool_version="x",
            moment="2026-01-01T00:00:00Z",
        )
        [package] = [p for p in document["packages"] if p["name"] == "left-pad"]
        assert package["checksums"] == [{"algorithm": "SHA256", "checksumValue": SHA256}]

    def test_an_algorithm_the_documents_do_not_name_gives_no_hash(self) -> None:
        assert SbomDocument._hash_of(_Kit.dependency(integrity="whirlpool:" + "a" * 128)) is None
        assert SbomDocument._hash_of(_Kit.dependency(integrity=None)) is None


class TestTimestamp:
    def test_source_date_epoch_sets_the_time_when_none_is_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", " 86400 ")
        assert SbomDocument._timestamp(None) == "1970-01-02T00:00:00Z"

    def test_an_explicit_moment_wins_and_a_bad_epoch_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "86400")
        assert SbomDocument._timestamp("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "soon")
        assert SbomDocument._timestamp(None).endswith("Z")
