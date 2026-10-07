"""Base-image and workload-image trust (advanced gap M4).

Before this, the images a Kubernetes manifest deploys were not read at all, and an image a
project runs with no signature or build attestation was recorded as `provenance: absent` and
reported nowhere. The probes: every pod template's containers are image dependencies, at any
nesting (Deployment, CronJob, bare Pod) and through a Kustomization's overrides; a Helm template
and an unrelated YAML file contribute nothing; a tag-only workload image is a policy finding; and
with `--online`, a runtime image whose registry serves no signature is one too, while a build
stage's image is not.
"""

from __future__ import annotations

from dataclasses import replace

from test_provenance import ProvenanceFixtures, ProvenanceHelpers

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Scope
from cordon_scanner.detect.provenance import UNSIGNED_IMAGE_RULE
from cordon_scanner.ecosystems.image import ImageEcosystem
from cordon_scanner.intel.registry_client import PackageFacts

DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      initContainers:
        - name: migrate
          image: ghcr.io/example/migrate:1.4
      containers:
        - name: web
          image: nginx:1.27
        - name: sidecar
          image: busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: report
              image: python:3.12-slim
"""


class WorkloadHelpers:
    @staticmethod
    def images(path: str, text: str) -> set[tuple[str, str, str | None]]:
        manifest = ImageEcosystem().parse_manifest(FileContent.from_bytes(path, text.encode()))
        return {(d.name, d.spec, d.integrity) for d in manifest.dependencies}


class TestKubernetesManifests:
    def test_every_container_at_any_depth(self) -> None:
        assert WorkloadHelpers.images("k8s/app.yaml", DEPLOYMENT) == {
            ("ghcr.io/example/migrate", "1.4", None),
            ("nginx", "1.27", None),
            (
                "busybox",
                "",
                "sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79",
            ),
            ("python", "3.12-slim", None),
        }

    def test_a_kustomization_override(self) -> None:
        text = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nimages:\n  - name: nginx\n    newName: registry.example.com/nginx\n    digest: sha256:"
            + "a" * 64
            + "\n"
        )
        assert WorkloadHelpers.images("deploy/kustomization.yaml", text) == {
            ("registry.example.com/nginx", "", "sha256:" + "a" * 64)
        }

    def test_a_helm_template_and_a_config_file_contribute_nothing(self) -> None:
        template = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: {{ .Values.image }}\n"
        assert WorkloadHelpers.images("deploy/templates/deployment.yaml", template) == set()
        assert (
            WorkloadHelpers.images("k8s/settings.yaml", "log_level: debug\nport: 8080\n") == set()
        )

    def test_the_conventional_places_are_read(self) -> None:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        for path in (
            "k8s/app.yaml",
            "deploy/prod/web.yml",
            "manifests/api.yaml",
            "web-deployment.yaml",
            "kustomization.yaml",
        ):
            assert EcosystemRegistry.manifest_ecosystem(path) == "image", path
        # An earlier ecosystem's file in the same directory stays that ecosystem's.
        assert EcosystemRegistry.manifest_ecosystem("deploy/chart/Chart.yaml") == "helm"

    def test_a_tag_only_workload_image_is_a_policy_finding(self, tmp_path) -> None:
        (tmp_path / "k8s").mkdir()
        (tmp_path / "k8s" / "app.yaml").write_text(DEPLOYMENT)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        unpinned = sorted(
            f.message.split(" runs ")[1].split(",")[0]
            for f in result.findings
            if f.rule_id == "POLICY.CONTAINER.UNPINNED_WORKLOAD_IMAGE.001"
        )
        assert unpinned == ["ghcr.io/example/migrate:1.4", "nginx:1.27", "python:3.12-slim"]


class TestUnsignedImages(ProvenanceFixtures):
    @staticmethod
    def image(scope: Scope):
        dependency = ProvenanceHelpers.dependency(ecosystem="image", integrity=None, version="1.27")
        return replace(
            dependency,
            name="nginx",
            purl="pkg:docker/nginx@1.27",
            scope=scope,
            declared_in="k8s/app.yaml",
        )

    def test_a_runtime_image_with_no_signature_is_reported(self, wire) -> None:
        wire(facts=PackageFacts(name="nginx", version="1.27", attested=False))
        assert ProvenanceHelpers.ids(self.image(Scope.RUNTIME)) == [UNSIGNED_IMAGE_RULE]

    def test_a_build_stage_image_is_not(self, wire) -> None:
        wire(facts=PackageFacts(name="nginx", version="1.27", attested=False))
        assert ProvenanceHelpers.ids(self.image(Scope.BUILD)) == []

    def test_offline_nothing_is_asked(self, wire) -> None:
        wire(facts=PackageFacts(name="nginx", version="1.27", attested=False))
        assert (
            ProvenanceHelpers.ids(
                self.image(Scope.RUNTIME), ProvenanceHelpers.context(offline=True)
            )
            == []
        )
