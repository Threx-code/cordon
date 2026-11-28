"""The images a CI pipeline file runs its jobs in, read from real files of public repositories (`ci_image_captures/CAPTURES.md`).

One table (`CiFiles.KINDS`) says which file kind is read by which reader; the image adapter's globs come from it. A
reference written with a variable is not one a registry can be asked about and is left out; a digest and a tag are told apart.
"""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.infra.ci_images import CiFiles
from cordon_scanner.ecosystems.infra.image import ImageEcosystem
from cordon_scanner.foundation.content import FileContent
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "ecosystems" / "coverage" / "ci_image_captures"

#: (capture, the path it has in a repository, the images it names as (name, tag or digest))
CASES = [
    (
        "gitlab-cli.gitlab-ci.yml",
        ".gitlab-ci.yml",
        {
            ("docker", "28-dind"),
            ("ghcr.io/canonical/snapcraft", "8_core24"),
            ("registry.gitlab.com/gitlab-org/cli", "latest"),
            (
                "registry.gitlab.com/gitlab-org/technical-writing/docs-gitlab-com/docs-gitlab-com-builder",
                "alpine-3.24-hugo-0.166.0",
            ),
            (
                "registry.gitlab.com/gitlab-org/technical-writing/docs-gitlab-com/lint-markdown",
                "alpine-3.24-vale-3.21.0-markdownlint2-0.23.2-lychee-0.24.2-rumdl-0.2.69",
            ),
        },
    ),
    (
        "pyeddl.Jenkinsfile",
        "Jenkinsfile",
        {("dhealth/dev-pyeddl-base-cpu", "e839f80f"), ("dhealth/dev-pyeddl-base-gpu", "e839f80f")},
    ),
    ("blueocean-plugin.Jenkinsfile", "Jenkinsfile", {("blueocean/blueocean", "build_env")}),
    (
        "flink.azure-pipelines.yml",
        "azure-pipelines.yml",
        {("apache/flink-ci-docker", "java_8_11_17_21_25_maven_386_3916_resolute_v3")},
    ),
    (
        "circleci-demo-docker.config.yml",
        ".circleci/config.yml",
        {("circleci/cci-demo-docker-primary", "0.0.2"), ("postgres", "9.4.1")},
    ),
    (
        "genai-for-developers.bitbucket-pipelines.yml",
        "bitbucket-pipelines.yml",
        {("python", "3.11-slim")},
    ),
    (
        "checkstyle.buildkite-pipeline.yml",
        ".buildkite/pipeline.yml",
        {("maven", "3.9-eclipse-temurin-21"), ("mcr.microsoft.com/openjdk/jdk", "21-ubuntu")},
    ),
    (
        "cloud-builders-go.cloudbuild.yaml",
        "cloudbuild.yaml",
        {
            ("alpine", "latest"),
            ("busybox", "latest"),
            ("gcr.io/cloud-builders/docker", "latest"),
            ("golang", "latest"),
        },
    ),
    (
        "drone-cli.drone.yml",
        ".drone.yml",
        {
            ("golang", "1.20"),
            ("plugins/docker", "latest"),
            ("plugins/github-release", "latest"),
            ("plugins/manifest", "latest"),
        },
    ),
    (
        "woodpecker-docker.yaml",
        ".woodpecker.yml",
        {
            ("golang", "1.27"),
            ("node", "26-alpine"),
            ("techknowlogick/xgo", "go-1.27.x"),
            ("woodpeckerci/plugin-docker-buildx", "6.1.2"),
        },
    ),
    (
        "argo-cd-server-deployment.yaml",
        "manifests/base/server/deployment.yaml",
        {("quay.io/argoproj/argocd", "latest")},
    ),
]


class Pipelines:
    @staticmethod
    def images(capture: str, path: str) -> set[tuple[str, str]]:
        content = FileContent.from_bytes(path, (CAPTURES / capture).read_bytes())
        manifest = ImageEcosystem().parse_manifest(content)
        return {(d.name, d.spec) for d in manifest.dependencies}


class TestEachFileKindIsRead:
    @pytest.mark.parametrize(("capture", "path", "expected"), CASES, ids=[c[0] for c in CASES])
    def test_the_images_a_real_file_names(
        self, capture: str, path: str, expected: set[tuple[str, str]]
    ) -> None:
        assert Pipelines.images(capture, path) == expected

    def test_a_digest_is_told_from_a_tag(self) -> None:
        content = FileContent.from_bytes(
            ".circleci/config.yml", (CAPTURES / "dropwizard.circleci-config.yml").read_bytes()
        )
        pinned = [d for d in ImageEcosystem().parse_manifest(content).dependencies if d.integrity]
        assert [(d.name, d.spec) for d in pinned] == [("cimg/openjdk", "25.0.5")]
        assert pinned[0].integrity is not None and pinned[0].integrity.startswith("sha256:")

    def test_a_reference_written_with_a_variable_is_left_out(self) -> None:
        names = {n for n, _ in Pipelines.images("gitlab-cli.gitlab-ci.yml", ".gitlab-ci.yml")}
        assert not any("$" in n for n in names)
        assert "golang" not in names  # `${GITLAB_DEPENDENCY_PROXY}golang:${GO_VERSION}`

    def test_an_azure_container_named_for_a_resource_is_not_an_image(self) -> None:
        names = {n for n, _ in Pipelines.images("flink.azure-pipelines.yml", "azure-pipelines.yml")}
        assert "flink-build-container" not in names


class TestTheTable:
    def test_every_capture_is_a_file_kind_the_table_takes(self) -> None:
        for _capture, path, _expected in CASES:
            assert CiFiles.reader(path) is not None, path

    def test_the_adapter_claims_every_glob_of_the_table(self) -> None:
        assert set(CiFiles.globs()) <= set(ImageEcosystem.manifest_globs)

    @pytest.mark.parametrize(
        ("path", "reader"),
        [
            ("services/api/.gitlab-ci.yml", "gitlab"),
            ("ci/Jenkinsfile.release", "jenkins"),
            (".azure-pipelines/build.yml", "azure"),
            ("deploy/azure-pipelines.yaml", "azure"),
            (".circleci/config.yml", "circleci"),
            ("app/.buildkite/pipeline.yaml", "buildkite"),
            ("a/cloudbuild.yml", "cloudbuild"),
            (".woodpecker.yml", "drone"),
            ("charts/app/templates/job.yaml", "kubernetes"),
            ("helm/app/deployment.yaml", "kubernetes"),
            ("overlays/base/x.yaml", "kubernetes"),
            ("web.k8s.yaml", "kubernetes"),
        ],
    )
    def test_a_path_goes_to_its_reader(self, path: str, reader: str) -> None:
        assert CiFiles.reader(path) == reader

    @pytest.mark.parametrize(
        "path", ["config.yml", "src/.circleci.yml", "notes/gitlab-ci.yml", "values/other.yaml"]
    )
    def test_another_file_is_no_pipeline(self, path: str) -> None:
        assert CiFiles.reader(path) is None
