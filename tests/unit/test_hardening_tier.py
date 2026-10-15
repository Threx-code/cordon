"""Pipeline, container and infrastructure posture is a hardening tier, off by default (review 98)."""

from __future__ import annotations

from dataclasses import replace

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config, ConfigParser, Policy
from cordon_scanner.core.models import Severity

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
