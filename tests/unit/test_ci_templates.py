"""The CI templates install the scanner they are released with, hash-verified, and never pipe a
download into a shell."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cordon_scanner.version import __version__

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = sorted(
    p
    for p in (ROOT / "ci").rglob("*")
    if p.is_file() and p.suffix in (".yml", ".yaml", ".groovy", ".sh")
)


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: str(p.relative_to(ROOT)))
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

    def test_any_pin_it_reads_is_the_one_the_release_writes(self, template: Path) -> None:
        """A template that fetches a pin file the release never generates fails at install, on
        every customer's first run, and nothing in this repository would notice."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "pin", ROOT / "scripts" / "pin_action_requirements.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        written = module.PIN.relative_to(ROOT).as_posix()
        text = template.read_text(encoding="utf-8")
        for read in re.findall(r"/v\$\{CORDON_VERSION\}/(\S+?requirements\.txt)", text):
            assert read == written, f"{template.name} fetches {read}; the release writes {written}"


class TestCiTemplates:
    """The tests of test_ci_templates.py that stood alone."""

    def test_the_pipe_image_copies_the_pin_the_release_writes(self) -> None:
        dockerfile = (ROOT / "ci" / "bitbucket" / "Dockerfile").read_text(encoding="utf-8")
        copied = re.findall(r"^COPY (\S+requirements\.txt)", dockerfile, re.MULTILINE)
        assert copied == ["action/requirements.txt"]

    def test_every_platform_the_backlog_names_has_a_template(self) -> None:
        names = {str(p.relative_to(ROOT / "ci")) for p in TEMPLATES}
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
