"""Attacks on the pipeline itself, across the systems that run one.

Every rule here has two tests and they are equally load-bearing: the shape is
reported, and the shape a careful pipeline uses instead is not. A CI rule that
fires on the documented safe spelling is worse than no rule, because the
workflows it accuses are the ones that read the documentation.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner


def rules_for(root, relative: str, body: str) -> set[str]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return {f.rule_id for f in Scanner().scan(root).findings}


def workflow(root, body: str) -> set[str]:
    return rules_for(root, ".github/workflows/ci.yml", body)


class TestAForkOnASelfHostedRunner:
    RULE = "SUSPECT.CI.SELF_HOSTED_FORK.001"

    def test_a_pull_request_job_on_a_self_hosted_runner_is_reported(self, tmp_path) -> None:
        assert self.RULE in workflow(
            tmp_path,
            "on:\n  pull_request:\n\njobs:\n"
            "  build:\n    runs-on: self-hosted\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: make build\n",
        )

    def test_a_hosted_runner_is_not(self, tmp_path) -> None:
        assert self.RULE not in workflow(
            tmp_path,
            "on:\n  pull_request:\n\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: make build\n",
        )

    def test_a_self_hosted_release_job_is_not(self, tmp_path) -> None:
        """No fork can trigger it, so no fork's code reaches the runner."""
        assert self.RULE not in workflow(
            tmp_path,
            "on:\n  push:\n    tags: ['v*']\n\njobs:\n"
            "  release:\n    runs-on: self-hosted\n    steps:\n"
            "      - run: make release\n",
        )

    def test_a_fork_guard_lowers_it_rather_than_silencing_it(self, tmp_path) -> None:
        findings = (
            [f for f in Scanner().scan(tmp_path).findings if f.rule_id == self.RULE]
            if workflow(
                tmp_path,
                "on:\n  pull_request:\n\njobs:\n"
                "  build:\n"
                "    if: github.event.pull_request.head.repo.full_name == github.repository\n"
                "    runs-on: self-hosted\n    steps:\n"
                "      - run: make build\n",
            )
            else []
        )
        assert findings, "the guard must lower the severity, not remove the finding"
        assert findings[0].severity.name == "MEDIUM"


class TestWorkflowRunCheckingOutItsTrigger:
    RULE = "SUSPECT.CI.WORKFLOW_RUN_CHECKOUT.001"

    def test_checking_out_the_triggering_head_is_reported(self, tmp_path) -> None:
        assert self.RULE in workflow(
            tmp_path,
            "on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\n\njobs:\n"
            "  comment:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.workflow_run.head_sha }}\n"
            "      - run: npm test\n",
        )

    def test_downloading_the_artefact_instead_is_not(self, tmp_path) -> None:
        """The documented safe shape: treat the first workflow's output as data."""
        assert self.RULE not in workflow(
            tmp_path,
            "on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\n\njobs:\n"
            "  comment:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "      - run: cat results.json\n",
        )


class TestAPublishingWorkflowThatRestoresACache:
    RULE = "SUSPECT.CI.CACHE_POISONING.001"

    def test_publishing_beside_a_restored_cache_is_reported(self, tmp_path) -> None:
        assert self.RULE in workflow(
            tmp_path,
            "on:\n  push:\n    tags: ['v*']\n\njobs:\n"
            "  release:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/cache@v4\n"
            "        with:\n          path: ~/.npm\n          key: npm-${{ runner.os }}\n"
            "      - run: npm publish\n",
        )

    def test_publishing_without_a_cache_is_not(self, tmp_path) -> None:
        assert self.RULE not in workflow(
            tmp_path,
            "on:\n  push:\n    tags: ['v*']\n\njobs:\n"
            "  release:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: npm publish\n",
        )

    def test_a_cache_in_a_test_workflow_is_not(self, tmp_path) -> None:
        assert self.RULE not in workflow(
            tmp_path,
            "on:\n  pull_request:\n\njobs:\n"
            "  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/cache@v4\n"
            "        with:\n          path: ~/.npm\n          key: npm-${{ runner.os }}\n"
            "      - run: npm test\n",
        )


class TestTokenPermissions:
    RULE = "POLICY.CI.WRITE_ALL_PERMISSIONS.001"

    def test_write_all_is_reported(self, tmp_path) -> None:
        assert self.RULE in workflow(
            tmp_path,
            "on: push\npermissions: write-all\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n",
        )

    def test_a_named_scope_is_not(self, tmp_path) -> None:
        assert self.RULE not in workflow(
            tmp_path,
            "on: push\npermissions:\n  contents: read\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n",
        )


class TestAReusableWorkflowCall:
    RULE = "POLICY.CI.UNPINNED_REUSABLE_WORKFLOW.001"
    SHA = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"

    def test_a_tagged_call_is_reported(self, tmp_path) -> None:
        assert self.RULE in workflow(
            tmp_path,
            "on: push\njobs:\n  build:\n    uses: acme/shared/.github/workflows/build.yml@v2\n",
        )

    def test_a_sha_pinned_call_is_not(self, tmp_path) -> None:
        assert self.RULE not in workflow(
            tmp_path,
            "on: push\njobs:\n"
            f"  build:\n    uses: acme/shared/.github/workflows/build.yml@{self.SHA}\n",
        )

    def test_a_local_call_is_not(self, tmp_path) -> None:
        """A path inside this repository is this repository's own code."""
        assert self.RULE not in workflow(
            tmp_path,
            "on: push\njobs:\n  build:\n    uses: ./.github/workflows/build.yml\n",
        )


class TestGitLabScriptInjection:
    RULE = "SUSPECT.CI.GITLAB_INJECTION.001"

    def test_a_commit_title_in_a_script_is_reported(self, tmp_path) -> None:
        assert self.RULE in rules_for(
            tmp_path,
            ".gitlab-ci.yml",
            'build:\n  script:\n    - echo "Building $CI_COMMIT_TITLE"\n',
        )

    def test_the_same_variable_in_a_rule_expression_is_not(self, tmp_path) -> None:
        """`rules:` decides whether the job runs. No shell parses it."""
        assert self.RULE not in rules_for(
            tmp_path,
            ".gitlab-ci.yml",
            'build:\n  rules:\n    - if: $CI_COMMIT_REF_NAME == "main"\n'
            "  script:\n    - make build\n",
        )


class TestAzureScriptInjection:
    RULE = "SUSPECT.CI.AZURE_INJECTION.001"

    def test_a_branch_macro_in_a_script_is_reported(self, tmp_path) -> None:
        assert self.RULE in rules_for(
            tmp_path,
            "azure-pipelines.yml",
            "steps:\n  - script: echo Building $(Build.SourceBranchName)\n",
        )

    def test_an_ordinary_variable_is_not(self, tmp_path) -> None:
        assert self.RULE not in rules_for(
            tmp_path,
            "azure-pipelines.yml",
            "steps:\n  - script: echo Building $(Build.BuildNumber)\n",
        )


class TestCircleScriptInjection:
    RULE = "SUSPECT.CI.CIRCLE_INJECTION.001"

    def test_a_branch_substitution_in_a_command_is_reported(self, tmp_path) -> None:
        assert self.RULE in rules_for(
            tmp_path,
            ".circleci/config.yml",
            "version: 2.1\njobs:\n  build:\n    steps:\n"
            "      - run: echo << pipeline.git.branch >>\n",
        )

    def test_the_same_value_in_a_parameter_is_not(self, tmp_path) -> None:
        assert self.RULE not in rules_for(
            tmp_path,
            ".circleci/config.yml",
            "version: 2.1\nworkflows:\n  main:\n    when:\n"
            "      equal: [main, << pipeline.git.branch >>]\n",
        )


class TestJenkinsScriptInjection:
    RULE = "SUSPECT.CI.JENKINS_INJECTION.001"

    def test_an_interpolated_branch_in_a_shell_step_is_reported(self, tmp_path) -> None:
        assert self.RULE in rules_for(
            tmp_path,
            "Jenkinsfile",
            "pipeline {\n  agent any\n  stages {\n    stage('build') {\n"
            '      steps {\n        sh "make build BRANCH=${env.BRANCH_NAME}"\n'
            "      }\n    }\n  }\n}\n",
        )

    def test_a_single_quoted_step_is_not(self, tmp_path) -> None:
        """Groovy does not interpolate a single-quoted string, so the shell
        receives the `$VAR` and expands it as data."""
        assert self.RULE not in rules_for(
            tmp_path,
            "Jenkinsfile",
            "pipeline {\n  agent any\n  stages {\n    stage('build') {\n"
            "      steps {\n        sh 'make build BRANCH=$BRANCH_NAME'\n"
            "      }\n    }\n  }\n}\n",
        )


class TestTheNewRulesAreDeclared:
    """Every rule that can fire has to be listed by `rules list`."""

    @pytest.mark.parametrize(
        "rule_id",
        [
            "SUSPECT.CI.SELF_HOSTED_FORK.001",
            "SUSPECT.CI.WORKFLOW_RUN_CHECKOUT.001",
            "SUSPECT.CI.CACHE_POISONING.001",
            "POLICY.CI.WRITE_ALL_PERMISSIONS.001",
            "POLICY.CI.UNPINNED_REUSABLE_WORKFLOW.001",
            "SUSPECT.CI.GITLAB_INJECTION.001",
            "SUSPECT.CI.AZURE_INJECTION.001",
            "SUSPECT.CI.CIRCLE_INJECTION.001",
            "SUSPECT.CI.JENKINS_INJECTION.001",
            "SUSPECT.CI.SECRET_OVERPROVISION.001",
        ],
    )
    def test_it_is_declared_with_a_remediation(self, rule_id: str) -> None:
        from cordon_scanner.detect.config_files import ConfigDetector

        declared = {r.id: r for r in ConfigDetector.declared_rules()}
        assert rule_id in declared
        assert declared[rule_id].remediation


class TestProximityIsGrouped:
    """`_near` interpolates both halves into one alternation, so an argument
    that is itself an alternation has to be grouped or the `|` it adds wins.

    Ungrouped, `_near("A|B", "S")` compiled as "A, or B near S, or S near A, or
    B": the first and last alternatives match alone, and the proximity
    requirement applies to nothing. It reached `MALWARE.CI.SECRET_EXFIL.001`,
    where the egress half stopped being required and a workflow forwarding its
    secret context to a reusable workflow was reported as exfiltration.
    """

    def test_the_first_half_alone_is_not_a_match(self) -> None:
        import re

        from cordon_scanner.detect.config_files import _near

        pattern = re.compile(_near("alpha|beta", "gamma"))
        assert pattern.search("alpha") is None
        assert pattern.search("beta") is None
        assert pattern.search("gamma") is None

    def test_either_half_near_the_other_is(self) -> None:
        import re

        from cordon_scanner.detect.config_files import _near

        pattern = re.compile(_near("alpha|beta", "gamma"))
        assert pattern.search("beta then gamma")
        assert pattern.search("gamma then alpha")

    def test_the_window_still_bounds_it(self) -> None:
        import re

        from cordon_scanner.detect.config_files import _near

        pattern = re.compile(_near("alpha|beta", "gamma", window=10))
        assert pattern.search("beta" + " " * 100 + "gamma") is None
