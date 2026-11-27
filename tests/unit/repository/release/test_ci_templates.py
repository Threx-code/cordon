"""The CI templates install the scanner they are released with, hash-verified, and never pipe a
download into a shell."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cordon_scanner.version import __version__
from support import ROOT as REPO

ROOT = REPO
TEMPLATES = sorted(
    p
    for p in (ROOT / "ci").rglob("*")
    if p.is_file() and p.suffix in (".yml", ".yaml", ".groovy", ".sh")
)


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.relative_to(ROOT).as_posix())
class TestEveryTemplate:
    def test_it_names_the_version_it_ships_with(self, template: Path) -> None:
        text = template.read_text(encoding="utf-8")
        versions = set(re.findall(r"(?<![\d.])(\d+\.\d+\.\d+)(?![\d.])", text)) - {"3.12"}
        assert versions <= {__version__}, (
            f"{template.name} names {sorted(versions)}, the release is {__version__}"
        )

    def test_it_never_pipes_a_download_into_a_shell(self, template: Path) -> None:
        text = template.read_text(encoding="utf-8")
        assert not re.search(r"(?:curl|wget)[^\n|]*\|\s*(?:ba|z)?sh\b", text)

    def test_any_pip_install_requires_hashes(self, template: Path) -> None:
        for line in template.read_text(encoding="utf-8").splitlines():
            if re.search(r"pip install[^\n]*\bcordon-scanner(?:==|[\s\"']|$)", line):
                pytest.fail(f"{template.name} installs by name, unverified: {line.strip()}")
        text = template.read_text(encoding="utf-8")
        if "pip install" in text:
            assert "--require-hashes" in text and "--no-deps" in text

    def test_every_severity_it_offers_is_one_the_scanner_reads(self, template: Path) -> None:
        """The CircleCI orb, the Bitbucket pipe and the Jenkins library offered `fail-on: none`,
        which the scanner refuses with exit 3: a pipeline that chose it failed every run."""
        from cordon_scanner.foundation.models import Severity

        valid = {s.name.lower() for s in Severity}
        text = template.read_text(encoding="utf-8")
        offered: set[str] = set()
        for group in re.findall(r"enum:\s*\[([^\]]*)\]", text):  # an orb parameter
            offered.update(v.strip() for v in group.split(","))
        for group in re.findall(r"in \[([^\]]*)\]", text):  # a groovy list
            offered.update(v.strip(" '\"") for v in group.split(","))
        for group in re.findall(r'case "\$\{\w+:-\w+\}" in ([\w|]+)\)', text):  # a shell case
            offered.update(group.split("|"))
        assert offered <= valid, f"{template.name} offers {sorted(offered - valid)}"

    def test_any_pin_it_reads_is_the_one_the_release_writes(self, template: Path) -> None:
        """A template that fetches a pin file the release never generates fails at install, on
        every customer's first run, and nothing in this repository would notice."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "pin", ROOT / "scripts" / "release" / "pin_action_requirements.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        written = {module.PIN.relative_to(ROOT).as_posix()}
        text = template.read_text(encoding="utf-8")
        for read in re.findall(r"/v\$\{CORDON_VERSION\}/(\S+?requirements\.txt)", text):
            assert read in written, (
                f"{template.name} fetches {read}; the release writes {sorted(written)}"
            )


class TestCiTemplates:
    """The tests of test_ci_templates.py that stood alone."""

    def test_the_pipe_image_copies_the_pin_the_release_writes(self) -> None:
        dockerfile = (ROOT / "ci" / "bitbucket" / "Dockerfile").read_text(encoding="utf-8")
        copied = re.findall(r"^COPY (\S+requirements\.txt)", dockerfile, re.MULTILINE)
        assert copied == ["action/requirements.txt"]

    def test_every_platform_the_backlog_names_has_a_template(self) -> None:
        names = {p.relative_to(ROOT / "ci").as_posix() for p in TEMPLATES}
        for expected in (
            "gitlab/cordon.gitlab-ci.yml",
            "bitbucket/pipe.sh",
            "azure/cordon-task.yml",
            "circleci/orb.yml",
            "jenkins/vars/cordonScan.groovy",
            "buildkite/pipeline.yml",
        ):
            assert expected in names

    def test_every_upload_identity_is_for_cordon_or_fixed_by_its_platform(self) -> None:
        """A token whose audience a cloud role trusts must never leave the job: CircleCI's default
        one, in particular. Each template asks for `cordon`, or uses the one its platform fixes."""
        circle = (ROOT / "ci" / "circleci" / "orb.yml").read_text(encoding="utf-8")
        assert "circleci run oidc get" in circle and 'CIRCLE_OIDC_TOKEN_V2"' not in circle
        buildkite = (ROOT / "ci" / "buildkite" / "pipeline.yml").read_text(encoding="utf-8")
        assert "--audience cordon" in buildkite
        azure = (ROOT / "ci" / "azure" / "cordon-task.yml").read_text(encoding="utf-8")
        assert "serviceConnectionId" in azure and "System.AccessToken" in azure
        jenkins = (ROOT / "ci" / "jenkins" / "vars" / "cordonScan.groovy").read_text(
            encoding="utf-8"
        )
        assert (
            "withCredentials([string(credentialsId: credentialsId, variable: 'CORDON_ID_TOKEN')])"
            in jenkins
        )

    def test_the_scanner_never_reads_circlecis_default_token(self) -> None:
        from cordon_scanner.cloud.auth import CloudAuth

        assert CloudAuth.ambient_identity_token({"CIRCLE_OIDC_TOKEN_V2": "x.y.z"}) is None
        assert CloudAuth.ambient_identity_token({"CORDON_ID_TOKEN": "a.b.c"}) == (
            "a.b.c",
            "environment",
        )

    def test_the_air_gapped_routes_never_reach_for_the_network(self) -> None:
        """R4: a runner with no internet must not hang on the intel feed or a download."""
        generic = (ROOT / "ci" / "generic" / "scan.sh").read_text(encoding="utf-8")
        assert "--network none" in generic and "CORDON_OFFLINE=1" in generic
        gitlab = (ROOT / "ci" / "gitlab" / "cordon.gitlab-ci.yml").read_text(encoding="utf-8")
        airgapped = gitlab.split(".cordon-airgapped:", 1)[1]
        assert 'CORDON_OFFLINE: "1"' in airgapped
        assert "curl" not in airgapped, "it must not inherit the download of the hash pin"

    def test_each_report_names_its_own_destination(self, tmp_path, capsys) -> None:
        """Every multi-format CI template writes several reports; each message must name the file it
        wrote, not the last destination on the command line."""
        from cordon_scanner.cli.main import CommandLine

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        sarif, junit = tmp_path / "out.sarif", tmp_path / "out.xml"
        CommandLine.main(
            ["scan", str(tmp_path), "--format", f"sarif:{sarif}", "--format", f"junit:{junit}"]
        )
        err = capsys.readouterr().err
        assert f"wrote sarif report to {sarif}" in err
        assert f"wrote junit report to {junit}" in err

    def test_the_action_uploads_through_the_environment_not_the_script(self) -> None:
        """Inputs reach the script through `env:`; an upload flag interpolated into `run:` would be
        the injection the Action already refuses for every other input."""
        action = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
        assert "CORDON_UPLOAD: ${{ inputs.upload }}" in action
        assert "CORDON_CLOUD_URL: ${{ inputs.cloud-url }}" in action
        scan = action.split("- name: Scan", 1)[1].split("- name: Upload SARIF", 1)[0]
        assert "${{ inputs." not in scan.split("run: |", 1)[1]

    def test_no_template_installs_a_signing_library(self) -> None:
        """Keyless signing is built into Cordon (`cloud/keyless`): a template that uploads installs
        Cordon and nothing else."""
        for path in (
            "action/action.yml",
            *(p.relative_to(ROOT).as_posix() for p in (ROOT / "ci").rglob("*.yml")),
        ):
            text = (ROOT / path).read_text(encoding="utf-8")
            assert "requirements-attest" not in text and "pip install sigstore" not in text, path

    def test_uploading_templates_sign_and_the_rest_cannot(self) -> None:
        """GitHub, GitLab, CircleCI and Buildkite get a Sigstore identity; Bitbucket, Azure and
        Jenkins have none public Sigstore accepts, which the docs say."""
        for path, needle in (
            ("action/action.yml", "id-token: write"),
            ("ci/gitlab/cordon.gitlab-ci.yml", "aud: sigstore"),
            ("ci/circleci/orb.yml", '"aud": "sigstore"'),
            ("ci/buildkite/pipeline.yml", "--audience sigstore"),
        ):
            assert needle in (ROOT / path).read_text(encoding="utf-8"), path


class TestTheMergeRequestReview:
    """GitLab and Bitbucket run the same pre-merge dependency review the GitHub Action does: on a merge or pull
    request only, against its base, each blocking change titled with its reason code where the host shows it."""

    def test_gitlab_reviews_merge_requests_into_code_quality(self) -> None:
        text = (ROOT / "ci/gitlab/cordon.gitlab-ci.yml").read_text(encoding="utf-8")
        job = text[text.index("cordon:dependency-review:") :]
        job = job[: job.index("\n\n#")]
        assert '--base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --format codeclimate' in job
        assert "codequality: gl-code-quality-review.json" in job
        assert (
            'if: $CI_PIPELINE_SOURCE == "merge_request_event"' in job
            and "CI_DEFAULT_BRANCH" not in job
        )

    def test_bitbucket_reviews_pull_requests_into_code_insights(self) -> None:
        pipe = (ROOT / "ci/bitbucket/pipe.sh").read_text(encoding="utf-8")
        assert '[ -n "${BITBUCKET_PR_ID:-}" ]' in pipe and "--format bitbucket" in pipe
        assert "python /insights.py cordon-review.json" in pipe
        docker = (ROOT / "ci/bitbucket/Dockerfile").read_text(encoding="utf-8")
        assert (
            "COPY ci/bitbucket/insights.py /insights.py" in docker
            and "install" in docker
            and " git" in docker
        )


class TestBitbucketCodeInsights:
    """`ci/bitbucket/insights.py`: the report is put first, then its annotations in batches of at most 100, all
    through Pipelines' proxy and never with a credential of its own."""

    @staticmethod
    def module():
        import importlib.util

        spec = importlib.util.spec_from_file_location("insights", ROOT / "ci/bitbucket/insights.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    class Opener:
        def __init__(self) -> None:
            self.sent: list[tuple[str, str, object, dict[str, str]]] = []

        def open(self, request, timeout: int = 0):
            import json

            self.sent.append(
                (
                    request.get_method(),
                    request.full_url,
                    json.loads(request.data),
                    dict(request.header_items()),
                )
            )

            class Response:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *a: object) -> None:
                    return None

            return Response()

    def test_the_report_then_annotations_in_batches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        insights = self.module()
        opener = self.Opener()
        monkeypatch.setattr(insights.CodeInsights, "opener", staticmethod(lambda: opener))
        for key, value in (
            ("BITBUCKET_REPO_OWNER", "acme"),
            ("BITBUCKET_REPO_SLUG", "app"),
            ("BITBUCKET_COMMIT", "a" * 40),
        ):
            monkeypatch.setenv(key, value)
        review = {
            "report": {"result": "FAILED"},
            "annotations": [{"external_id": f"c{i}"} for i in range(230)],
        }
        assert insights.CodeInsights.post(review) == 230
        methods = [m for m, _, _, _ in opener.sent]
        assert methods == ["PUT", "POST", "POST", "POST"]
        assert [len(b) for _, _, b, _ in opener.sent[1:]] == [100, 100, 30]
        base = (
            "http://api.bitbucket.org/2.0/repositories/acme/app/commit/"
            + "a" * 40
            + "/reports/cordon-dependency-review"
        )
        assert opener.sent[0][1] == base and opener.sent[1][1] == base + "/annotations"
        assert not any("Authorization" in h for _, _, _, h in opener.sent)

    @pytest.mark.parametrize("value", ["", "..", "a/b", "."])
    def test_a_path_segment_cannot_leave_its_place(self, value: str) -> None:
        with pytest.raises(ValueError):
            self.module().CodeInsights.segment(value)
