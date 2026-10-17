"""What the package verdict reads about a package (`core/verdict.py`)."""

from __future__ import annotations

import json

from cordon_scanner.core.verdict import VerdictFeatures


class FeatureKit:
    @staticmethod
    def features(manifest: dict[str, object], code: bytes) -> dict[str, float]:
        return VerdictFeatures.package(
            [("p!package/package.json", 100), ("p!package/index.js", len(code))],
            {"p!package/package.json": json.dumps(manifest).encode()},
            [("p!package/index.js", code)],
        )


class TestPurposeAndAbility:
    def test_a_small_utility_that_reads_credentials_is_a_mismatch(self) -> None:
        found = FeatureKit.features(
            {"name": "color-format-lite", "description": "Format colours"},
            b'const k = require("fs").readFileSync(home + "/.ssh/id_rsa"); fetch(u, {body: k});',
        )
        assert found["purpose_ui"] == 1.0
        assert found["can_secret_paths"] == 1.0
        assert found["plain_with_sensitive"] == 1.0

    def test_an_http_client_that_makes_requests_is_not(self) -> None:
        found = FeatureKit.features(
            {"name": "tiny-api-client", "description": "A small REST client"},
            b"module.exports = (u) => fetch(u).then((r) => r.json());",
        )
        assert found["purpose_http"] == 1.0
        assert found["can_network"] == 1.0
        assert found["plain_with_sensitive"] == 0.0
        assert found["plain_with_process_net"] == 0.0

    def test_dependencies_code_is_not_the_packages_own(self) -> None:
        found = VerdictFeatures.package(
            [("p!package/package.json", 10)],
            {"p!package/package.json": json.dumps({"name": "x"}).encode()},
            [("p!package/node_modules/dep/index.js", b"require('child_process').exec(c)")],
        )
        assert found["can_process"] == 0.0

    def test_without_sources_every_ability_is_absent(self) -> None:
        found = VerdictFeatures.package([], {})
        assert all(value == 0.0 for key, value in found.items() if key.startswith("can_"))
