"""Pipeline, container and infrastructure posture is a hardening tier, off by default (review 98)."""

from __future__ import annotations

from dataclasses import replace

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config, ConfigParser, Policy
from cordon_scanner.foundation.models import Severity

WORKFLOW = (
    "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - run: curl -fsSL https://get.example.com/install.sh | bash\n"
)


class HardeningHelpers:
    @staticmethod
    def severities(tmp_path, config: Config) -> list[Severity]:
        target = tmp_path / ".github" / "workflows" / "ci.yml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(WORKFLOW, encoding="utf-8")
        return [
            f.severity
            for f in Scanner(config).scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001"
        ]


class TestHardeningTier:
    def test_by_default_a_ci_fetch_and_run_is_recorded(self, tmp_path) -> None:
        found = HardeningHelpers.severities(
            tmp_path, Config.default().with_overrides(use_cache=False)
        )
        assert found and all(severity == Severity.LOW for severity in found)

    def test_with_hardening_it_keeps_its_severity(self, tmp_path) -> None:
        config = Config.default().with_overrides(use_cache=False)
        config = config.with_overrides(policy=replace(config.policy, hardening=True))
        found = HardeningHelpers.severities(tmp_path, config)
        assert found and any(severity > Severity.LOW for severity in found)

    def test_the_stricter_merge_keeps_hardening_on(self) -> None:
        merged = ConfigParser._stricter_policy(Policy(hardening=True), Policy())
        assert merged.hardening


class BuildDefinitionHelpers:
    #: A file that downloads and evaluates code: what any rule reads as a dropper.
    FETCH_AND_RUN = (
        'const https = require("https");\n'
        'https.get("https://releases.example.invalid/tool.js", (res) => {\n'
        '  let body = "";\n'
        '  res.on("data", (part) => (body += part));\n'
        '  res.on("end", () => eval(body));\n'
        "});\n"
    )

    @staticmethod
    def suspicious(tmp_path):
        from cordon_scanner.foundation.models import Category

        (tmp_path / "fetch.js").write_text(BuildDefinitionHelpers.FETCH_AND_RUN, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        found = [
            f
            for f in result.findings
            if f.category is Category.SUSPICIOUS and f.severity > Severity.LOW
        ]
        assert found, "the fixture has to produce a finding above LOW"
        return found[0]

    @staticmethod
    def graded(finding, path: str, policy: Policy) -> Severity:
        from cordon_scanner.engine.pipeline.ceilings import Ceilings

        moved = replace(finding, location=replace(finding.location, path=path))
        [out] = Ceilings.hardening_tier([moved], policy)
        return out.severity


class TestBuildDefinitions:
    """A generic code finding in a container build file or a pipeline is posture, not an attack."""

    def test_in_a_dockerfile_of_any_name_it_is_recorded(self, tmp_path) -> None:
        finding = BuildDefinitionHelpers.suspicious(tmp_path)
        for path in ("Dockerfile", "ci/docker/ubuntu-24.04.Dockerfile", "a.tgz!x/Containerfile"):
            assert BuildDefinitionHelpers.graded(finding, path, Policy()) is Severity.LOW

    def test_in_a_pipeline_it_is_recorded(self, tmp_path) -> None:
        finding = BuildDefinitionHelpers.suspicious(tmp_path)
        for path in (".github/workflows/release.yml", "ci/.gitlab-ci.yml", "Jenkinsfile"):
            assert BuildDefinitionHelpers.graded(finding, path, Policy()) is Severity.LOW

    def test_in_source_it_keeps_its_grade(self, tmp_path) -> None:
        finding = BuildDefinitionHelpers.suspicious(tmp_path)
        for path in ("lib/fetch.js", "docker/entrypoint.sh", ".github/scripts/fetch.js"):
            assert BuildDefinitionHelpers.graded(finding, path, Policy()) is finding.severity

    def test_with_hardening_it_keeps_its_grade(self, tmp_path) -> None:
        finding = BuildDefinitionHelpers.suspicious(tmp_path)
        graded = BuildDefinitionHelpers.graded(finding, "Dockerfile", Policy(hardening=True))
        assert graded is finding.severity

    def test_a_malicious_finding_is_never_lowered(self, tmp_path) -> None:
        from cordon_scanner.foundation.models import Category

        finding = replace(BuildDefinitionHelpers.suspicious(tmp_path), category=Category.MALICIOUS)
        assert BuildDefinitionHelpers.graded(finding, "Dockerfile", Policy()) is finding.severity
