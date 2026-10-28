"""The infrastructure rules: Terraform and other IaC, CloudFormation and Ansible configuration
that opens a service to the internet, grants what it should not, or runs a fetched script.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.detect.infra.config_paths import DOCKER_PATHS, IAC_PATHS, K8S_MARKER
from cordon_scanner.detect.infra.config_rule import ConfigRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)

if TYPE_CHECKING:
    pass

_ADMIN_PORT = (
    r"(?:from_port|to_port|FromPort|ToPort|destination_port_range|port|Port)"
    r'[ \t]{0,32}[=:][ \t]{0,32}\[?[ \t]{0,32}"?'
    r"(?:22|23|135|139|445|1433|1521|2375|2376|2379|2380|3306|3389|5432|5900"
    r"|5984|6379|6443|8020|9000|9200|11211|27017|0|\*|-1)(?!\w)"
)
"""Ports where "reachable from the entire internet" is the finding.

Remote administration, databases, orchestration APIs, and the wildcards that
mean every port. Deliberately NOT 80, 443, 8080 or 8443: a public service
listening on those is a public service, and reporting it teaches people that
this rule is wrong -- which is what they conclude about the rest of the pack
too.
"""

_OPEN_RANGE = (
    r"(?:cidr_blocks|source_ranges|CidrIp|CidrIpv6|source_address_prefix)"
    r'[ \t]{0,32}[=:][ \t]{0,32}\[?[ \t]{0,32}"?(?:0\.0\.0\.0/0|::/0|\*|Internet)"?'
)
"""A source range that is the whole internet."""

_PUBLIC_INGRESS = (
    f"(?:{_OPEN_RANGE}[^{{}}]{{0,400}}{_ADMIN_PORT}|{_ADMIN_PORT}[^{{}}]{{0,400}}{_OPEN_RANGE})"
)
"""The range AND the port, in either order, inside one block."""

CFN_MARKER = b"AWSTemplateFormatVersion"
"""What identifies a CloudFormation template.

Same reasoning as the Kubernetes marker. A template is a `.yaml` or `.json`
file that can live anywhere -- `infra/`, `cfn/`, `templates/`, or the
repository root -- and its own declaration is the only reliable way to know
what it is."""

ANSIBLE_PATHS = (
    "**/playbook*.yml",
    "**/playbook*.yaml",
    "**/playbooks/**/*.yml",
    "**/playbooks/**/*.yaml",
    "**/roles/**/tasks/*.yml",
    "**/roles/**/tasks/*.yaml",
    "**/site.yml",
    "**/site.yaml",
)

CFN_PATHS = (
    "**/*.template",
    "**/cloudformation/**/*.yaml",
    "**/cloudformation/**/*.yml",
    "**/cfn/**/*.yaml",
    "**/cfn/**/*.yml",
)

INFRASTRUCTURE_RULES: tuple[ConfigRule, ...] = (
    # -- Infrastructure --------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.IAC.PUBLIC_INGRESS.001",
        references=(references.IMPROPER_ACCESS_CONTROL, references.EXPOSED_RESOURCE),
        title="Ingress permitted from the entire internet",
        message=(
            "A security rule allows traffic from 0.0.0.0/0. Combined with an "
            "administrative port this exposes the service to untargeted internet-wide "
            "scanning, which finds it within minutes rather than days."
        ),
        remediation=(
            "Restrict the source range to known networks, or place the service behind "
            "a bastion or a private endpoint."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # IPv4 *and* IPv6, and the other names cloud providers give the same
        # field. The IPv4-only form meant `cidr_blocks = ["::/0"]` -- the whole
        # internet, spelled the other way -- produced nothing at all, which is a
        # one-character evasion of a HIGH rule.
        pattern=ConfigRule._p(
            # The port as well as the range, in either order, within the same
            # block. The message has always said the danger is "combined with
            # an administrative port" and the pattern never checked one, so a
            # load balancer allowing 443 from the internet -- which is the
            # entire point of a load balancer -- was reported at HIGH beside an
            # SSH port open to the world. 206 findings across 37 of the 1,427
            # corpus repositories, the largest single class in the pass.
            #
            # `[^{}]` keeps the two halves inside one resource block. A cidr in
            # one rule and a port in the next are not the same rule, and a brace
            # is where one ends in every format this matches.
            _PUBLIC_INGRESS
        ),
        paths=IAC_PATHS,
        content_marker=K8S_MARKER,
        outbound_exempt=True,
    ),
    ConfigRule(
        rule_id="SUSPECT.IAC.PRIVILEGED.001",
        references=(
            references.KUBERNETES_POD_SECURITY,
            references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
        ),
        title="Privileged container or host namespace",
        message=(
            "This workload runs privileged, or shares a host namespace. Either makes "
            "the container boundary decorative: a process inside it can reach the "
            "host directly, so a compromise of the workload is a compromise of the "
            "node."
        ),
        remediation=(
            "Remove the privilege. If a specific capability is genuinely required, "
            "add that one capability rather than granting all of them."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"privileged:\s*true|hostPID:\s*true|hostNetwork:\s*true|hostIPC:\s*true"
        ),
        paths=IAC_PATHS + DOCKER_PATHS,
        content_marker=K8S_MARKER,
    ),
)


CLOUDFORMATION_RULES: tuple[ConfigRule, ...] = (
    # -- CloudFormation ---------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.IAC.IAM_WILDCARD.001",
        references=(references.IMPROPER_ACCESS_CONTROL,),
        title="Policy grants every action or every resource",
        message=(
            "This policy grants `*` for actions or attaches an administrator "
            "policy. A role with it can do anything the account can do, including "
            "removing the trail that would show what it did."
        ),
        remediation=(
            "Enumerate the actions the workload performs. Start from what it needs "
            "rather than from everything and subtract."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            # JSON and YAML (`"Action": "*"`), and HCL -- `Action = "*"` inside jsonencode, and an
            # aws_iam_policy_document's `actions = ["*"]`. Not `not_actions`, which is the opposite.
            r"(?<![\w])[\"']?[Aa]ctions?[\"']?[ \t]{0,32}[:=][ \t]{0,32}\[?[ \t]{0,32}[\"']\*[\"']"
            r"|[\"']?Action[\"']?[ \t]{0,32}:[ \t]{0,32}\n[ \t]{0,40}-[ \t]{0,32}[\"']?\*"
            # `AdministratorAccess` where it is being ATTACHED, not where it is being
            # looked up or matched. A bare word matched it everywhere:
            # `ministryofjustice/modernisation-platform` asks whether the caller is an
            # admin with `can(regex("superadmin|AdministratorAccess", ...))` three times
            # -- a CHECK, and the opposite of a grant -- and finds the existing SSO role
            # with `name_regex = "AWSReservedSSO_AdministratorAccess_.*"`, which is a
            # data-source filter. Eleven of thirty-three findings in one sample.
            #
            # Two grant shapes: the managed-policy ARN, and the name as a complete
            # quoted string, which is how a permission-set list and a map key are
            # written. `|AdministratorAccess"` has a pipe in front of it and
            # `"AWSReservedSSO_AdministratorAccess_"` an underscore, so neither is one.
            r"|policy/AdministratorAccess\b"
            r"|[\"']AdministratorAccess[\"']"
            r"|[\"']?(?:iam|sts)\:\*[\"']?"
        ),
        paths=IAC_PATHS + CFN_PATHS,
        content_marker=CFN_MARKER,
    ),
)


ANSIBLE_RULES: tuple[ConfigRule, ...] = (
    # -- Ansible ----------------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.IAC.ANSIBLE_FETCH_EXEC.001",
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, references.CODE_INJECTION),
        title="Play downloads and runs a script on every host",
        message=(
            "This play fetches content and pipes it into a shell. Ansible runs it "
            "on every host in the inventory, usually with escalated privileges, so "
            "whoever controls the URL controls the fleet."
        ),
        remediation=(
            "Use get_url with a checksum, then run the verified file. The checksum "
            "is what makes the download reviewable."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"(?:shell|command|raw)[ \t]{0,32}:[^\n]{0,200}"
            r"(?:curl|wget)[^\n]{0,200}\|[ \t]{0,32}(?:sudo[ \t]{1,8})?(?:sh|bash|python[0-9.]{0,4})"
        ),
        paths=ANSIBLE_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.IAC.ANSIBLE_TLS_UNVERIFIED.001",
        references=(references.IMPROPER_CERT_VALIDATION,),
        title="Task turns off TLS certificate verification",
        message=(
            "A task sets validate_certs off, so what it downloads or talks to is accepted from "
            "whoever answers -- on every host the play reaches. A network attacker between a host "
            "and the server can serve anything."
        ),
        remediation=(
            "Leave validate_certs on. For an internal certificate authority, install its "
            "certificate on the hosts (or pass ca_path) instead of turning verification off."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(
            r"(?m)^[ \t]+validate_certs[ \t]*:[ \t]*['\"]?(?:no|false|False|FALSE|off)['\"]?[ \t]*(?:#.*)?$"
        ),
        paths=ANSIBLE_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.IAC.ANSIBLE_UNSIGNED_PACKAGES.001",
        references=(
            references.INSUFFICIENT_VERIFICATION,
            references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
        ),
        title="Task installs packages without checking their signatures",
        message=(
            "A task turns off the package manager's signature check (disable_gpg_check, "
            "allow_unauthenticated, an apt source marked trusted=yes). The repository's signing "
            "key is what tells a real package from one injected on the way, and every host the "
            "play reaches installs whatever arrives, as root."
        ),
        remediation=(
            "Keep signature checks on; import the repository's signing key (rpm_key, a signed-by "
            "keyring for apt) so its packages verify."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"(?m)^[ \t]+(?:disable_gpg_check|allow_unauthenticated)[ \t]*:[ \t]*['\"]?(?:yes|true|True|TRUE|on)['\"]?[ \t]*(?:#.*)?$"
            r"|\[[^\]\n]{0,120}\btrusted=yes\b[^\]\n]{0,120}\]"
        ),
        paths=ANSIBLE_PATHS,
    ),
)


__all__ = [
    "ANSIBLE_PATHS",
    "ANSIBLE_RULES",
    "CFN_MARKER",
    "CFN_PATHS",
    "CLOUDFORMATION_RULES",
    "INFRASTRUCTURE_RULES",
]
