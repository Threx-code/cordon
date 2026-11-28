"""The image adapter on inputs that are odd, cut short or not an image: what it skips, what it says, and the registry it treats as public (`ecosystems/infra/image.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.infra.image import Dockerfile, Kubernetes
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["image"]


class TestShellWords:
    def test_words_split_on_whitespace_outside_quotes_and_escapes_are_kept(self) -> None:
        assert Dockerfile.shell_words('A="x y"  B=\\ z C') == ['A="x y"', "B=\\ z", "C"]

    def test_a_single_quoted_backslash_is_not_an_escape(self) -> None:
        assert Dockerfile.shell_words("A='a\\' b") == ["A='a\\'", "b"]


class TestDockerfile:
    def read(self, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("Dockerfile", text))

    def test_a_copy_from_something_that_is_not_an_image_reference_is_an_error_with_its_line(
        self,
    ) -> None:
        manifest = self.read("FROM alpine:3.19\nCOPY --from=Not/A/Valid/Ref//x /a /b\n")
        assert manifest.parse_error.startswith(
            "line 2: 'Not/A/Valid/Ref//x' is not an image reference"
        )

    def test_an_add_whose_list_form_is_broken_declares_nothing(self) -> None:
        manifest = self.read('FROM alpine:3.19\nADD ["https://example.invalid/a.tgz" /dst\n')
        assert [d.name for d in manifest.dependencies] == ["alpine"]

    def test_an_add_of_a_local_file_or_an_unset_variable_is_not_a_remote_source(self) -> None:
        manifest = self.read("FROM alpine:3.19\nADD local.tgz /dst\nADD ${URL} /dst\n")
        assert [d.name for d in manifest.dependencies] == ["alpine"]

    def test_the_image_adapter_has_no_lockfile(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("Dockerfile.lock", ""))
        assert graph.entries == () and not graph.parse_error

    def test_only_docker_hub_is_a_public_registry_anyone_can_register_on(self) -> None:
        assert _Kit.adapter().is_public_registry(None) is True
        assert _Kit.adapter().is_public_registry("registry.example.invalid") is False


class TestKustomize:
    def read(self, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("k8s/kustomization.yaml", text))

    def test_an_image_override_without_a_name_is_skipped_and_a_new_tag_is_applied(self) -> None:
        text = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nimages:\n"
            "  - {newTag: '1'}\n  - name: nginx\n    newTag: '1.25'\n"
        )
        assert [(d.name, d.spec) for d in self.read(text).dependencies] == [("nginx", "1.25")]

    def test_a_pod_nested_past_the_limit_is_not_followed(self) -> None:
        deep: Any = {"image": "alpine:3"}
        for _ in range(40):
            deep = {"spec": deep}
        assert list(Kubernetes.images(deep, "x")) == []
