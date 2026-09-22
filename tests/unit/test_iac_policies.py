"""Every infrastructure policy, proved by its own samples.

A policy that stops matching is invisible: the scan still succeeds, the report
is still clean, and the gate is green precisely because the check is broken.
That is the failure this project exists to report in other people's pipelines,
so the same standard applies here -- each policy carries a block it must report
and a block it must not, and both run on every push.

The block extraction is tested separately and end to end, because a policy that
works on a sample and never sees a real file is the same failure one layer down.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.detect.iac import (
    Block,
    IacPolicy,
    blocks_for,
    cloudformation_blocks,
    compose_services,
    kubernetes_blocks,
    terraform_blocks,
)
from cordon_scanner.detect.iac_policies import CURATED, all_policies, generated_meta

POLICIES = all_policies()


def _block(policy: IacPolicy, body: str) -> Block:
    return Block(kind=policy.resources[0], name="example", body=body, start=0)


@pytest.mark.parametrize("policy", POLICIES, ids=[p.id for p in POLICIES])
class TestEveryPolicy:
    def test_it_reports_the_block_it_is_about(self, policy: IacPolicy) -> None:
        assert policy.evaluate(_block(policy, policy.bad)) is not None, (
            f"{policy.id} did not fire on its own positive sample. A policy that "
            f"matches nothing reports nothing and looks exactly like a clean scan."
        )

    def test_it_leaves_the_remediated_block_alone(self, policy: IacPolicy) -> None:
        assert policy.evaluate(_block(policy, policy.good)) is None, (
            f"{policy.id} fired on the configuration its own remediation asks for. "
            f"A policy that reports the fix teaches people to ignore it."
        )

    def test_it_says_what_to_do(self, policy: IacPolicy) -> None:
        assert policy.remediation.strip()
        assert policy.message.strip()
        assert policy.title.strip()


class TestTheGeneratedHalf:
    """Built from the provider schemas by `scripts/build_iac_policies.py`.

    The point of generating them is that the resource list is a fact rather than
    a memory: a policy naming an attribute the provider does not have can never
    fire, and looks exactly like a clean scan.
    """

    def test_there_are_more_generated_than_curated(self) -> None:
        assert len(POLICIES) - len(CURATED) > len(CURATED)

    def test_the_set_records_what_it_was_built_from(self) -> None:
        meta = generated_meta()
        assert meta.get("providers"), "no provenance: which schemas produced these?"
        assert meta.get("policy_count") == len(POLICIES) - len(CURATED)

    def test_a_generated_policy_does_not_shadow_a_curated_one(self) -> None:
        curated = {policy.id for policy in CURATED}
        generated = {policy.id for policy in POLICIES} - curated
        assert not (curated & generated)


class TestTheTableItself:
    def test_identifiers_are_unique(self) -> None:
        ids = [p.id for p in POLICIES]
        duplicated = sorted({i for i in ids if ids.count(i) > 1})
        assert not duplicated, f"two policies share an id: {duplicated}"

    def test_every_policy_names_a_resource(self) -> None:
        for policy in POLICIES:
            assert policy.resources, policy.id

    def test_a_policy_cannot_claim_two_things(self) -> None:
        """`forbid` and `require` are different findings with different fixes."""
        with pytest.raises(ValueError):
            IacPolicy(
                id="X",
                title="t",
                message="m",
                remediation="r",
                severity=POLICIES[0].severity,
                confidence=POLICIES[0].confidence,
                resources=("aws_s3_bucket",),
                forbid=("a",),
                require=("b",),
                bad="a",
                good="",
            )

    def test_a_policy_must_claim_something(self) -> None:
        with pytest.raises(ValueError):
            IacPolicy(
                id="X",
                title="t",
                message="m",
                remediation="r",
                severity=POLICIES[0].severity,
                confidence=POLICIES[0].confidence,
                resources=("aws_s3_bucket",),
                bad="a",
                good="",
            )


class TestTerraformBlocks:
    def test_a_resource_is_found_with_its_type_and_name(self) -> None:
        blocks = list(terraform_blocks('resource "aws_s3_bucket" "logs" {\n  acl = "private"\n}\n'))
        assert [(b.kind, b.name) for b in blocks] == [("aws_s3_bucket", "logs")]

    def test_nested_blocks_do_not_end_it_early(self) -> None:
        text = (
            'resource "aws_instance" "web" {\n'
            '  metadata_options {\n    http_tokens = "required"\n  }\n'
            '  tags = { Name = "web" }\n'
            "}\n"
        )
        (block,) = terraform_blocks(text)
        assert "http_tokens" in block.body
        assert "Name" in block.body

    def test_a_brace_in_a_string_does_not_end_it(self) -> None:
        text = (
            'resource "aws_iam_policy" "p" {\n'
            '  policy = "{\\"Statement\\": []}"\n'
            '  description = "after"\n'
            "}\n"
        )
        (block,) = terraform_blocks(text)
        assert "description" in block.body

    def test_a_heredoc_policy_document_does_not_end_it(self) -> None:
        text = (
            'resource "aws_iam_role" "r" {\n'
            '  assume_role_policy = <<EOF\n{\n  "Version": "2012-10-17"\n}\nEOF\n'
            '  description = "after"\n'
            "}\n"
        )
        (block,) = terraform_blocks(text)
        assert "description" in block.body

    def test_two_resources_are_two_blocks(self) -> None:
        text = (
            'resource "aws_ebs_volume" "a" {\n  encrypted = true\n}\n'
            'resource "aws_ebs_volume" "b" {\n  size = 8\n}\n'
        )
        assert [b.name for b in terraform_blocks(text)] == ["a", "b"]

    def test_an_unclosed_block_is_skipped_rather_than_raising(self) -> None:
        assert list(terraform_blocks('resource "aws_ebs_volume" "a" {\n  size = 8\n')) == []


class TestOtherFormats:
    def test_a_kubernetes_document_is_typed_by_its_kind(self) -> None:
        text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec: {}\n"
        (block,) = kubernetes_blocks(text)
        assert (block.kind, block.name) == ("k8s:Pod", "app")

    def test_a_multi_document_file_yields_one_block_each(self) -> None:
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
            "---\n"
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: b\n"
        )
        assert [b.kind for b in kubernetes_blocks(text)] == ["k8s:Pod", "k8s:Service"]

    def test_a_cloudformation_resource_is_typed_by_its_type(self) -> None:
        text = (
            "Resources:\n"
            "  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n"
        )
        (block,) = cloudformation_blocks(text)
        assert block.kind == "cfn:AWS::S3::Bucket"

    def test_a_compose_service_is_a_block(self) -> None:
        text = "services:\n  web:\n    image: nginx\n    privileged: true\n"
        (block,) = compose_services(text)
        assert (block.kind, block.name) == ("compose:service", "web")

    def test_a_yaml_file_that_is_none_of_them_yields_nothing(self) -> None:
        text = "name: ci\non: push\njobs: {}\n"
        assert blocks_for("x.yml", text, text.encode()) == ()


class TestEndToEnd:
    """The policies have to reach a file on disk, not only a sample."""

    def config(self) -> Config:
        return Config.default().with_overrides(use_cache=False)

    def test_an_unencrypted_database_is_reported(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "main" {\n'
            '  identifier = "prod"\n'
            "  allocated_storage = 20\n"
            "}\n",
            encoding="utf-8",
        )
        found = {f.rule_id for f in Scanner(self.config()).scan(tmp_path).findings}
        assert "POLICY.IAC.ENCRYPT_AT_REST.AWS_DB_INSTANCE.001" in found

    def test_the_encrypted_one_beside_it_is_not(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "main" {\n'
            '  identifier = "prod"\n'
            "  storage_encrypted = true\n"
            "}\n",
            encoding="utf-8",
        )
        found = {f.rule_id for f in Scanner(self.config()).scan(tmp_path).findings}
        assert "POLICY.IAC.ENCRYPT_AT_REST.AWS_DB_INSTANCE.001" not in found

    def test_one_bad_resource_does_not_implicate_its_neighbour(self, tmp_path) -> None:
        """The reason blocks exist: a finding belongs to the resource that earned it."""
        (tmp_path / "main.tf").write_text(
            'resource "aws_ebs_volume" "encrypted" {\n  encrypted = true\n}\n'
            'resource "aws_ebs_volume" "plain" {\n  size = 8\n}\n',
            encoding="utf-8",
        )
        findings = [
            f
            for f in Scanner(self.config()).scan(tmp_path).findings
            if f.rule_id == "POLICY.IAC.ENCRYPT_AT_REST.AWS_EBS_VOLUME.001"
        ]
        assert len(findings) == 1
        assert "plain" in findings[0].message

    def test_a_privileged_pod_is_reported_once(self, tmp_path) -> None:
        """`SUSPECT.IAC.PRIVILEGED.001` owns this shape. The policy table
        deliberately does not add a second rule for it -- two findings about one
        line is how a report stops being read."""
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
            "  containers:\n    - name: app\n      securityContext:\n"
            "        privileged: true\n",
            encoding="utf-8",
        )
        findings = [
            f for f in Scanner(self.config()).scan(tmp_path).findings if "PRIVILEGED" in f.rule_id
        ]
        assert [f.rule_id for f in findings] == ["SUSPECT.IAC.PRIVILEGED.001"]

    def test_a_compose_service_on_the_host_network_is_reported(self, tmp_path) -> None:
        """The socket mount belongs to `SUSPECT.IAC.HOST_MOUNT.001`; the host
        network namespace was not reported by anything before this table."""
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  ci:\n    image: runner\n    network_mode: host\n",
            encoding="utf-8",
        )
        found = {f.rule_id for f in Scanner(self.config()).scan(tmp_path).findings}
        assert "SUSPECT.COMPOSE.HOST_NETWORK.001" in found

    def test_a_public_cloudformation_bucket_is_reported(self, tmp_path) -> None:
        (tmp_path / "template.yaml").write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\n"
            "Resources:\n"
            "  Bucket:\n    Type: AWS::S3::Bucket\n"
            "    Properties:\n      AccessControl: PublicRead\n",
            encoding="utf-8",
        )
        found = {f.rule_id for f in Scanner(self.config()).scan(tmp_path).findings}
        assert "SUSPECT.CFN.PUBLIC_STORAGE.BUCKET.001" in found

    def test_a_terraform_file_that_meets_every_control_reports_nothing(self, tmp_path) -> None:
        """Encrypted is not the whole of it. The generated set also asks which
        key, and a volume on the platform's key is a different decision from one
        on a key you hold."""
        (tmp_path / "ok.tf").write_text(
            'resource "aws_ebs_volume" "a" {\n'
            "  encrypted  = true\n"
            "  kms_key_id = aws_kms_key.this.arn\n"
            "  size       = 8\n"
            "}\n",
            encoding="utf-8",
        )
        iac = [f for f in Scanner(self.config()).scan(tmp_path).findings if f.detector == "iac"]
        assert iac == []

    def test_the_unencrypted_one_reports_both_controls(self, tmp_path) -> None:
        (tmp_path / "bad.tf").write_text(
            'resource "aws_ebs_volume" "a" {\n  size = 8\n}\n', encoding="utf-8"
        )
        found = {
            f.rule_id for f in Scanner(self.config()).scan(tmp_path).findings if f.detector == "iac"
        }
        assert "POLICY.IAC.ENCRYPT_AT_REST.AWS_EBS_VOLUME.001" in found
        assert "POLICY.IAC.CMEK.AWS_EBS_VOLUME.001" in found


class TestTheFormatsRealFilesAreWrittenIn:
    """Measured against 353 templates from AWS's own sample repositories.

    The first run saw 65% of the 3,080 resources they declare, and every miss
    was one of two shapes: a JSON template, which is what most of AWS's own
    examples are, and a resource whose key carries a trailing comment. A format
    the extractor does not read is a format no policy is evaluated against.
    """

    def test_a_json_template_is_read(self) -> None:
        text = (
            '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket",'
            ' "Properties": {"AccessControl": "PublicRead"}}}}'
        )
        (block,) = blocks_for("template.json", text, text.encode())
        assert block.kind == "cfn:AWS::S3::Bucket"
        assert block.name == "Bucket"

    def test_a_json_template_reports(self, tmp_path) -> None:
        (tmp_path / "template.json").write_text(
            '{"Resources": {"Db": {"Type": "AWS::RDS::DBInstance",'
            ' "Properties": {"PubliclyAccessible": true}}}}',
            encoding="utf-8",
        )
        found = {
            f.rule_id
            for f in Scanner(Config.default().with_overrides(use_cache=False))
            .scan(tmp_path)
            .findings
        }
        assert "SUSPECT.CFN.PUBLIC_ACCESS.DBINSTANCE.001" in found, sorted(found)

    def test_a_commented_resource_key_is_still_a_resource(self) -> None:
        text = (
            "Resources:\n"
            "  BackupVault: # cannot be deleted with data\n"
            "    Type: AWS::Backup::BackupVault\n"
            "    Properties:\n      BackupVaultName: example\n"
        )
        (block,) = blocks_for("t.yaml", text, text.encode())
        assert block.name == "BackupVault"

    def test_a_bicep_resource_is_read(self) -> None:
        text = (
            "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
            "  name: 'example'\n"
            "  properties: {\n    supportsHttpsTrafficOnly: false\n  }\n"
            "}\n"
        )
        (block,) = blocks_for("main.bicep", text, text.encode())
        assert (block.kind, block.name) == ("azure:Microsoft.Storage/storageAccounts", "stg")

    def test_a_bicep_file_reports(self, tmp_path) -> None:
        (tmp_path / "main.bicep").write_text(
            "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
            "  name: 'example'\n"
            "  properties: {\n    supportsHttpsTrafficOnly: false\n  }\n"
            "}\n",
            encoding="utf-8",
        )
        found = {
            f.rule_id
            for f in Scanner(Config.default().with_overrides(use_cache=False))
            .scan(tmp_path)
            .findings
        }
        assert any("AZURE.PLAINTEXT" in rule for rule in found), found

    def test_an_arm_template_reads_nested_resources(self) -> None:
        text = (
            '{"resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "ex",'
            ' "properties": {},'
            ' "resources": [{"type": "Microsoft.Storage/storageAccounts/blobServices",'
            ' "name": "default", "properties": {}}]}]}'
        )
        kinds = [b.kind for b in blocks_for("azuredeploy.json", text, text.encode())]
        assert kinds == [
            "azure:Microsoft.Storage/storageAccounts",
            "azure:Microsoft.Storage/storageAccounts/blobServices",
        ]

    def test_an_ordinary_json_file_is_not_a_template(self) -> None:
        text = '{"name": "demo", "dependencies": {"left-pad": "1.0.0"}}'
        assert blocks_for("package.json", text, text.encode()) == ()


#: One file per format, each with a `forbid` policy that has a line of its own.
_LOCATION_CASES = {
    "main.tf": (
        "# a comment that makes the header long enough to matter\n"
        'resource "aws_db_instance" "with_a_deliberately_long_name" {\n'
        '  identifier = "prod"\n'
        "  allocated_storage = 20\n"
        "  publicly_accessible = true\n"
        "}\n"
    ),
    "main.bicep": (
        "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'example'\n"
        "  properties: {\n"
        "    allowBlobPublicAccess: true\n"
        "  }\n"
        "}\n"
    ),
    "pod.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
        "  hostNetwork: true\n  containers:\n    - name: app\n"
    ),
    "template.yaml": (
        "Resources:\n  Database:\n    Type: AWS::RDS::DBInstance\n"
        "    Properties:\n      DBInstanceClass: db.t3.micro\n"
        "      PubliclyAccessible: true\n"
    ),
    "docker-compose.yml": ("services:\n  ci:\n    image: runner:1.2\n    network_mode: host\n"),
}


class TestAFindingPointsAtItsOwnLine:
    """A `forbid` finding has to name the line the reader has to change.

    `Block.body` is a slice of the file for four of the six formats and the
    match offset is relative to it, so mapping one back needs where the body
    begins -- which for Terraform and Bicep is after the opening brace, a whole
    header line past `Block.start`. Measured against Azure's quickstart
    templates: `publicNetworkAccess: 'Enabled'` on line 20 reported as line 15,
    and every such finding in those two formats out by the length of its own
    header.

    Asserted as a property rather than per case, because a line number that is
    close is indistinguishable from one that is right until somebody follows it.
    """

    @pytest.mark.parametrize("filename", sorted(_LOCATION_CASES))
    def test_the_span_is_where_it_says_it_is(self, tmp_path, filename: str) -> None:
        body = _LOCATION_CASES[filename]
        (tmp_path / filename).write_text(body, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False)
        located = [
            f
            for f in Scanner(config).scan(tmp_path).findings
            if f.detector == "iac" and f.evidence.span is not None
        ]
        assert located, f"{filename} produced no locatable infrastructure finding"
        raw = body.encode()
        for finding in located:
            start, end = finding.evidence.span
            assert raw[start:end].decode() == finding.evidence.snippet.strip(), (
                f"{finding.rule_id}: the span does not hold the text the finding shows"
            )
            assert finding.location.line == raw[:start].count(b"\n") + 1, (
                f"{finding.rule_id}: reported line {finding.location.line} is not "
                f"the line the match is on"
            )
