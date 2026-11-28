"""Compose and Helm on the shapes they write less often: block scalars, quoted service names, includes, unset image variables, chart requirements and archives (`ecosystems/infra/compose.py`, `helm.py`)."""

from __future__ import annotations

import io
import tarfile
from typing import Any

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str | bytes) -> FileContent:
        raw = text if isinstance(text, bytes) else text.encode("utf-8")
        return FileContent.from_bytes(path, raw, Limits())

    @staticmethod
    def compose(text: str) -> Any:
        return EcosystemRegistry.BY_ID["image"].parse_manifest(_Kit.fc("compose.yaml", text))

    @staticmethod
    def helm() -> Any:
        return EcosystemRegistry.BY_ID["helm"]


class TestCompose:
    def test_a_block_scalar_command_with_a_blank_line_does_not_end_the_service_early(self) -> None:
        text = (
            "services:\n  web:\n    image: nginx\n    command: >\n      echo hi\n\n      more\n"
            "    ports: ['80:80']\n"
        )
        assert [d.name for d in _Kit.compose(text).dependencies] == ["nginx"]

    def test_a_quoted_service_name_is_read_and_one_that_never_closes_is_refused(self) -> None:
        ok = "services:\n  \"web\":\n    image: nginx\n  'db':\n    image: postgres\n"
        assert {d.name for d in _Kit.compose(ok).dependencies} == {"nginx", "postgres"}
        broken = 'services:\n  "web":\n    image: nginx\n  "bad:\n    image: x\n'
        assert "is neither a key nor a list item" in _Kit.compose(broken).parse_error

    def test_a_quoted_name_with_no_colon_after_it_is_not_a_service(self) -> None:
        manifest = _Kit.compose('services:\n  "web"\n    image: nginx\n')
        assert manifest.dependencies == ()

    def test_an_indented_first_line_is_not_a_mapping(self) -> None:
        assert "must be a mapping" in _Kit.compose("  a: 1\n").parse_error

    def test_an_include_with_no_services_is_named_as_a_source(self) -> None:
        manifest = _Kit.compose("include:\n  - other.yaml\n")
        assert "includes other.yaml" in manifest.sources

    def test_an_image_that_names_an_unset_variable_is_said_not_guessed(self) -> None:
        manifest = _Kit.compose("services:\n  web:\n    image: ${REG}/nginx\n")
        assert manifest.dependencies == ()
        assert any("takes its image from $REG" in s for s in manifest.sources)

    def test_a_line_shallower_than_the_first_of_its_block_is_passed_over(self) -> None:
        text = "services:\n  web:\n      image: nginx\n    ports: x\n"
        manifest = _Kit.compose(text)
        assert [d.name for d in manifest.dependencies] == ["nginx"]

    def test_a_line_indented_deeper_than_its_key_is_passed_over(self) -> None:
        manifest = _Kit.compose("services:\n  web:\n    image: nginx\n      deeper: x\n")
        assert [d.name for d in manifest.dependencies] == ["nginx"]


class TestChartFiles:
    def read(self, path: str, text: str, **others: str) -> Any:
        files = {path: _Kit.fc(path, text), **{p: _Kit.fc(p, t) for p, t in others.items()}}
        return _Kit.helm().parse_in_tree(files[path], files)

    def test_a_chart_without_a_name_and_version_is_refused(self) -> None:
        manifest = self.read("Chart.yaml", "description: x\n")
        assert manifest.parse_error == "a Chart.yaml without name and version"

    def test_dependencies_that_are_not_a_list_are_refused(self) -> None:
        manifest = self.read("Chart.yaml", "name: c\nversion: 1\ndependencies: {a: b}\n")
        assert manifest.parse_error == "`dependencies` is not a list"

    def test_a_requirements_yaml_beside_the_chart_that_cannot_be_read_is_an_error(self) -> None:
        manifest = self.read(
            "Chart.yaml", "apiVersion: v1\nname: c\nversion: 1\n", **{"requirements.yaml": "- a\n"}
        )
        assert "invalid requirements.yaml beside it" in manifest.parse_error

    def test_a_dependency_with_no_name_is_skipped(self) -> None:
        text = (
            "apiVersion: v2\nname: c\nversion: 1\ndependencies:\n"
            "  - {repository: 'https://charts.example.invalid'}\n"
            "  - {name: redis, version: 17.0.0, repository: 'https://charts.example.invalid'}\n"
        )
        assert [d.name for d in self.read("Chart.yaml", text).dependencies] == ["redis"]

    def test_a_lock_that_is_not_a_mapping_is_refused_as_a_manifest_too(self) -> None:
        manifest = _Kit.helm().parse_manifest(_Kit.fc("Chart.lock", "- a\n"))
        assert manifest.parse_error.startswith("invalid Chart.lock")

    def test_a_lock_dependency_without_name_and_version_is_refused(self) -> None:
        text = f"dependencies:\n  - {{name: a}}\ndigest: sha256:{'0' * 64}\n"
        graph = _Kit.helm().parse_lockfile(_Kit.fc("Chart.lock", text))
        assert graph.parse_error == "a locked dependency without name and version"

    def test_only_https_oci_and_named_repositories_are_registries(self) -> None:
        adapter = _Kit.helm()
        assert adapter.is_registry_host(None) is False
        assert adapter.is_registry_host("https://charts.example.invalid") is True
        assert adapter.is_registry_host("file://../charts") is False


class TestChartArchives:
    def archive(self, members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, data in members.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        return buffer.getvalue()

    def lock(self, raw: bytes) -> Any:
        return _Kit.helm().parse_lockfile(_Kit.fc("charts/redis-17.0.0.tgz", raw))

    def test_an_archive_that_is_not_gzip_is_refused(self) -> None:
        assert self.lock(b"not an archive").parse_error.startswith("not a readable chart archive")

    def test_an_archive_without_a_chart_yaml_is_refused(self) -> None:
        assert self.lock(self.archive({"redis/values.yaml": b"a: 1\n"})).parse_error == (
            "a chart archive without its Chart.yaml"
        )

    def test_an_archive_with_more_members_than_the_limit_is_read_no_further(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.ecosystems.infra.helm import ChartArchive

        monkeypatch.setattr(ChartArchive, "MAX_MEMBERS", 0)
        raw = self.archive({"a": b"x", "redis/Chart.yaml": b"name: redis\nversion: 1\n"})
        assert self.lock(raw).parse_error == "a chart archive without its Chart.yaml"

    def test_the_chart_yaml_names_the_archive_and_its_hash_is_the_integrity(self) -> None:
        raw = self.archive({"redis/Chart.yaml": b"name: redis\nversion: 17.0.0\n"})
        [entry] = self.lock(raw).entries
        assert (entry.name, entry.version) == ("redis", "17.0.0")
        assert entry.integrity.startswith("sha256:")
