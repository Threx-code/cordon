"""GitHub Actions workflows and action files on the shapes that are odd or cut short (`ecosystems/infra/actions.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.infra.actions import ActionReference, ActionsFile
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["actions"]

    @staticmethod
    def workflow(text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(".github/workflows/ci.yml", text))

    @staticmethod
    def action(text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("action.yml", text))


class TestReferences:
    def test_a_reference_chosen_at_run_time_or_with_one_part_names_no_action(self) -> None:
        assert ActionReference.declare("${{ matrix.action }}@v1", None, "uses") is None
        assert ActionReference.declare("owner@v1", None, "uses") is None


class TestIncompleteJobs:
    def test_a_file_with_no_jobs_key_is_not_judged(self) -> None:
        assert ActionsFile.incomplete_job("name: x\non: push\n") is None

    def test_a_jobs_key_followed_by_another_top_level_key_holds_no_job(self) -> None:
        text = "jobs:\nname: after\n"
        assert ActionsFile.incomplete_job(text) == "a workflow whose `jobs` holds no job"

    def test_steps_that_end_where_the_next_key_is_less_indented_are_read_as_one_list(self) -> None:
        job = [
            "  build:",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "    timeout-minutes: 5",
        ]
        assert ActionsFile.incomplete_step(job) is False


class TestActionFiles:
    def test_a_docker_action_without_an_image_is_refused_as_cut_short(self) -> None:
        manifest = _Kit.action("name: a\nruns:\n  using: docker\n")
        assert manifest.parse_error == "a docker action without `image`"

    def test_a_docker_action_built_from_its_own_dockerfile_says_so(self) -> None:
        manifest = _Kit.action("name: a\nruns:\n  using: docker\n  image: Dockerfile\n")
        assert "container built from Dockerfile" in manifest.sources

    def test_an_image_key_inside_a_run_script_is_script_text_not_a_container(self) -> None:
        text = (
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n          cat <<EOF\n          image: docker://evil/x:1\n          EOF\n"
        )
        assert _Kit.workflow(text).dependencies == ()


class TestAdapter:
    def test_a_github_url_is_a_registry_host_and_another_is_decided_by_the_base_rule(self) -> None:
        adapter = _Kit.adapter()
        assert adapter.is_registry_host("https://github.com/actions/checkout") is True
        assert adapter.is_registry_host("https://example.invalid/x") is False

    def test_workflows_have_no_lockfile(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc(".github/workflows/ci.yml", "on: push\n"))
        assert graph.entries == () and not graph.parse_error
