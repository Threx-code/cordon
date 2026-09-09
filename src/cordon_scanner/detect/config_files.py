"""CI, container and infrastructure configuration.

These files decide what runs, with what privileges, reachable by whom. They are
usually reviewed less carefully than application code and they frequently hold
more authority than it, which is a poor combination.

The checks here concentrate on the small number of mistakes that convert a
configuration file into a compromise:

**CI.** A workflow that checks out untrusted code and then runs with a writable
token. A secret context serialised into a command. An action pinned to a mutable
tag, so what executes is whatever the tag points at today.

**Containers.** A build that fetches a script and pipes it to a shell, so the
image contains whatever a remote host served at build time. A secret passed as a
build argument, which is recorded in the image history. A base image pinned by
tag rather than digest.

**Infrastructure.** Storage and databases open to the public internet.
Privileged containers and host mounts, which make a container boundary
decorative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
    Capability,
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.paths import basename
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.core.walker import PathGlob
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit


@dataclass(frozen=True, slots=True)
class ConfigRule:
    @staticmethod
    def _p(pattern: str) -> re.Pattern[bytes]:
        return re.compile(pattern.encode("utf-8"), re.MULTILINE | re.IGNORECASE)

    rule_id: str
    title: str
    message: str
    remediation: str
    severity: Severity
    confidence: Confidence
    category: Category
    pattern: re.Pattern[bytes]
    paths: tuple[str, ...]
    capabilities: tuple[Capability, ...] = ()

    content_marker: bytes | None = None
    """Bytes that identify this kind of file regardless of where it sits.

    A path glob is a guess about a convention. `IAC_PATHS` matched `k8s/` and
    `kubernetes/` and missed `deploy/`, `manifests/`, `charts/`, `overlays/`,
    `base/`, `infra/`, a bare `deployment.yaml` at the repository root, and
    `k8s/prod/pod.yaml` one directory deeper -- so byte-identical privileged pod
    manifests were found or missed according to the name of their parent
    directory.

    A Kubernetes manifest is identifiable from its content: it declares
    `apiVersion:` and `kind:`. That is one cheap substring test and it is correct
    everywhere. The globs are kept as a fast path, and this as the answer.
    """


def _near(first: str, second: str, window: int = 400) -> str:
    """Two patterns within `window` characters of each other, in either order.

    Proximity in one direction is not a rule, it is half of one.
    `curl -d "$TOKEN"` and `TOKEN=$SECRET` followed by `curl -d "$TOKEN"` are
    the same step doing the same thing, and a pattern that only reads forwards
    catches whichever half the author happened to write second.

    The window is what keeps this a claim about one step rather than about a
    file: a pipeline that uses a secret in one job and calls curl in an
    unrelated one is not this.
    """
    return f"(?:{first}[\\s\\S]{{0,{window}}}?{second}|{second}[\\s\\S]{{0,{window}}}?{first})"


CI_PATHS = (
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
    "**/.gitlab-ci.yml",
    "**/.gitlab-ci.yaml",
    "**/Jenkinsfile",
    "**/Jenkinsfile.*",
    "**/azure-pipelines.yml",
    "**/azure-pipelines.yaml",
    "**/.azure-pipelines/*.yml",
    "**/.circleci/config.yml",
    "**/.circleci/config.yaml",
    "**/bitbucket-pipelines.yml",
    "**/.buildkite/*.yml",
    "**/.buildkite/*.yaml",
    "**/cloudbuild.yaml",
    "**/cloudbuild.yml",
    "**/.drone.yml",
    "**/.woodpecker.yml",
)

DOCKER_PATHS = (
    "**/Dockerfile",
    "**/Dockerfile.*",
    "**/Containerfile",
    "**/docker-compose.yml",
    "**/docker-compose.yaml",
    "**/compose.yml",
    "**/compose.yaml",
)

IAC_PATHS = (
    "**/*.tf",
    "**/*.tfvars",
    "**/k8s/**/*.yaml",
    "**/k8s/**/*.yml",
    "**/kubernetes/**/*.yaml",
    "**/kubernetes/**/*.yml",
    "**/*.k8s.yaml",
    "**/helm/**/*.yaml",
    "**/manifests/**/*.yaml",
    "**/manifests/**/*.yml",
    "**/deploy/**/*.yaml",
    "**/deploy/**/*.yml",
    "**/charts/**/*.yaml",
    "**/overlays/**/*.yaml",
    "**/base/**/*.yaml",
)
"""Fast path only. `**/k8s/*.yaml` matched files directly in a `k8s` directory
and not `k8s/prod/pod.yaml` one level down, which is why every entry now uses
`**`. Correctness comes from K8S_MARKER, not from this list."""

CFN_MARKER = b"AWSTemplateFormatVersion"
"""What identifies a CloudFormation template.

Same reasoning as the Kubernetes marker. A template is a `.yaml` or `.json`
file that can live anywhere -- `infra/`, `cfn/`, `templates/`, or the
repository root -- and its own declaration is the only reliable way to know
what it is."""

ANSIBLE_MARKER = b"hosts:"
"""What identifies an Ansible play.

Weaker than the others, and paired with a task keyword in every rule that uses
it, because `hosts:` alone appears in plenty of unrelated configuration."""

HELM_PATHS = (
    "**/Chart.yaml",
    "**/Chart.yml",
    "**/values.yaml",
    "**/values.yml",
    "**/templates/*.yaml",
    "**/templates/*.yml",
    "**/charts/**/*.yaml",
    "**/charts/**/*.yml",
)
"""Helm chart files.

Templates render to Kubernetes manifests, so the manifest rules apply to them
through the `apiVersion` marker once rendered -- but a template carrying Go
templating often does not contain `apiVersion` literally, and `Chart.yaml` and
`values.yaml` never do. These paths are how the chart itself gets read."""

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

K8S_MARKER = b"apiVersion"
"""What actually identifies a Kubernetes manifest.

Checked in the first few kilobytes of any `.yaml`/`.yml` file, wherever it
lives. Byte-identical privileged pod manifests were previously found in `k8s/`
and missed in `deploy/`, `manifests/` and the repository root."""

CONTENT_MARKER_BYTES = 4096
"""How far into a file to look for a content marker.

A manifest declares `apiVersion` at the top. Scanning further would cost more
and find only files that mention the word in passing."""


RULES: tuple[ConfigRule, ...] = (
    # -- CI -------------------------------------------------------------
    ConfigRule(
        rule_id="MALWARE.CI.SECRET_EXFIL.001",
        title="CI workflow serialises its secret context",
        message=(
            "This workflow renders the whole secret context into a command. Every "
            "secret available to the job is materialised as a string at that point, "
            "where it can be printed, sent anywhere, or written to an artefact. "
            "There is no legitimate reason to serialise the entire context."
        ),
        remediation=(
            "Reference individual secrets by name. If a step genuinely needs several, "
            "pass each one explicitly so the set is visible in review."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.MALICIOUS,
        # `toJSON(secrets)` dumps everything and was the only shape caught. The
        # targeted form -- bind one named secret to an env var, then send it --
        # is what a real exfil step looks like, and it was invisible: the audit's
        # `env: TOK: ${{ secrets.NPM_TOKEN }}` with `curl -d "$TOK"` produced
        # nothing.
        #
        # Matched within a bounded window rather than across the file, so a
        # workflow that legitimately uses a secret and separately calls curl in
        # an unrelated job does not trip it.
        pattern=ConfigRule._p(
            r"toJSON\s{0,4}\(\s{0,4}secrets\s{0,4}\)"
            r"|\$\{\{\s{0,4}secrets\s{0,4}\}\}|"
            + _near(
                r"\$\{\{\s{0,4}secrets\.\w{1,64}[^\n]{0,80}\}\}",
                r"(?:curl|wget|nc\s|Invoke-WebRequest|/dev/tcp)",
            )
        ),
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="MALWARE.CI.SECRET_EXFIL.002",
        title="Pipeline sends a masked variable off the runner",
        message=(
            "This pipeline references a protected or masked variable and, in the "
            "same block, sends data off the runner. Masking hides a value in the "
            "log; it does nothing about where the value goes. Every CI system has "
            "its own syntax for secrets and its own users who assume masking is a "
            "control -- this covers the ones that are not GitHub Actions."
        ),
        remediation=(
            "Confirm the destination. A secret that a step both reads and transmits "
            "has left the boundary the CI system was protecting it inside."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        category=Category.MALICIOUS,
        # GitLab exposes variables as `$NAME`; Jenkins binds them with
        # `credentials()` or `withCredentials`; Azure uses `$(NAME)`. Each is
        # paired with an egress verb inside a bounded window, the same shape the
        # GitHub rule uses, so a pipeline that legitimately uses a secret in one
        # job and calls curl in an unrelated one is not caught.
        pattern=ConfigRule._p(
            _near(
                r"(?:credentials\s{0,4}\(|withCredentials\b"
                r"|\$\{?[A-Z_]{0,24}(?:TOKEN|SECRET|PASSWORD|APIKEY|API_KEY|CREDENTIAL)"
                r"[A-Z_]{0,24}\}?"
                r"|\$\([A-Za-z_]{0,24}(?:Token|Secret|Password|ApiKey)[A-Za-z_]{0,24}\))",
                r"(?:curl|wget|nc\s|Invoke-WebRequest|/dev/tcp|scp\s)",
            )
        ),
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.EXPRESSION_INJECTION.001",
        title="Untrusted pipeline input interpolated into a shell command",
        message=(
            "A field an outside contributor controls -- a pull request title, a "
            "branch name, a commit message -- is interpolated directly into a "
            "script. The interpolation happens before the shell sees the line, so "
            "the value is not an argument to the command; it is part of it, and a "
            "title containing a semicolon runs whatever follows with the job's "
            "token and secrets."
        ),
        remediation=(
            "Pass the value through an environment variable and reference it as "
            '"$VAR" inside the script. The interpolation then happens after the '
            "shell has parsed the line, so the value stays data."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"\$\{\{\s{0,4}github\.(?:event\.(?:issue|pull_request|comment|"
            r"discussion|review)\.(?:title|body|user\.login)"
            r"|event\.head_commit\.message|head_ref)"
        ),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.ARTIFACT_POISONING.001",
        title="Untrusted build uploads or restores a cache it can control",
        message=(
            "This workflow runs contributor code under `pull_request_target` and "
            "also writes an artefact or a cache entry. The job has the base "
            "repository's secrets and a writable token, so anything it stores is "
            "trusted by later runs -- which turns one pull request into a "
            "persistent foothold in the pipeline."
        ),
        remediation=(
            "Do not upload artefacts or write caches from a job that runs "
            "contributor code with elevated permissions. Split the build from the "
            "privileged step."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"pull_request_target[\s\S]{0,1200}?"
            r"(?:actions/upload-artifact|actions/cache|save-cache|restore-cache)"
        ),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.PR_TARGET.001",
        title="Workflow uses pull_request_target with an explicit checkout",
        message=(
            "pull_request_target runs with a writable token and the base "
            "repository's secrets, while this workflow also checks out a specific "
            "ref. If that ref is the pull request head, untrusted code executes with "
            "full write access to the repository. This is the most commonly "
            "exploited misconfiguration in CI."
        ),
        remediation=(
            "Use pull_request for anything that runs contributor code. If "
            "pull_request_target is required to comment or label, do not check out "
            "the head ref in the same job."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(r"pull_request_target"),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.CI.UNPINNED_ACTION.001",
        title="Action referenced by a mutable tag",
        message=(
            "A third-party action is referenced by tag rather than by commit SHA. A "
            "tag can be moved, so what executes in this pipeline is whatever the tag "
            "points at today, with access to the job's secrets. Pinning by tag "
            "delegates that decision permanently to whoever controls the tag."
        ),
        remediation=(
            "Pin to a full commit SHA and record the version in a trailing comment: "
            "uses: owner/action@<sha>  # v4.1.0"
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(
            r"uses:\s*(?!\./)(?!actions/)[\w.\-]+/[\w.\-]+@(?!\b[0-9a-f]{40}\b)[\w.\-]+"
        ),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.FETCH_EXEC.001",
        title="CI step fetches and executes remote content",
        message=(
            "A pipeline step downloads something and runs it. The code that executes "
            "is whatever the remote host serves at that moment, with the job's "
            "credentials, and it is not captured by review or by any lockfile."
        ),
        remediation=(
            "Vendor the script, or pin it by digest and verify the digest before running it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # Two shapes, because there are two ways to run what you fetched. The
        # pipe is the famous one; downloading to a path and then executing that
        # path is the same act written over three clauses, and it produced only
        # the `low` unpinned-base note.
        pattern=ConfigRule._p(
            r"(?:curl|wget)[^\n|]{0,200}\|\s{0,4}(?:sudo\s{1,4})?(?:ba)?sh"
            # No backreference tying the downloaded path to the executed one.
            # It would be more precise, and the pattern validator refuses
            # backreferences for every rule pack -- engine patterns are held to
            # the same rule, which is the point of holding them to it. Fetching
            # to a file and making something executable in the same command is
            # signal enough; the pair has no innocent reading.
            r"|(?:curl|wget)[^\n]{0,200}?(?:-o|--output|-O)\s{1,4}[^\s]{1,200}"
            r"[^\n]{0,200}chmod\s{1,4}\+x"
        ),
        paths=CI_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    # -- Containers ------------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.CONTAINER.FETCH_EXEC.001",
        title="Image build fetches and executes remote content",
        message=(
            "This build downloads a script and pipes it to a shell. The image ends "
            "up containing whatever the remote host served at build time, which is "
            "not recorded anywhere and cannot be reproduced or reviewed."
        ),
        remediation=(
            "Copy the script into the build context and run it from there, so it is "
            "versioned and reviewable, or verify a pinned digest before executing."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # The same two shapes as the CI rule above. A Dockerfile that downloads
        # to a path and then runs that path is doing exactly what the piped form
        # does, written over three clauses joined by `&&`, and it produced only
        # the `low` unpinned-base note.
        pattern=ConfigRule._p(
            r"(?:curl|wget)[^\n|]{0,200}\|\s{0,4}(?:sudo\s{1,4})?(?:ba)?sh"
            # No backreference tying the downloaded path to the executed one.
            # It would be more precise, and the pattern validator refuses
            # backreferences for every rule pack -- engine patterns are held to
            # the same rule, which is the point of holding them to it. Fetching
            # to a file and making something executable in the same command is
            # signal enough; the pair has no innocent reading.
            r"|(?:curl|wget)[^\n]{0,200}?(?:-o|--output|-O)\s{1,4}[^\s]{1,200}"
            r"[^\n]{0,200}chmod\s{1,4}\+x"
        ),
        paths=DOCKER_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="SUSPECT.CONTAINER.BUILD_SECRET.001",
        title="Secret passed as a build argument",
        message=(
            "A credential is supplied through ARG or ENV. Build arguments are "
            "recorded in the image history and readable by anyone who can pull the "
            "image, so the secret ships with it."
        ),
        remediation=(
            "Use BuildKit secret mounts, which are not persisted into any layer, or "
            "supply the credential at runtime."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"^\s*(?:ARG|ENV)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*="
        ),
        paths=DOCKER_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="POLICY.CONTAINER.UNPINNED_BASE.001",
        title="Base image referenced by tag rather than digest",
        message=(
            "The base image is pinned by tag. A tag is mutable, so two builds of the "
            "same Dockerfile can produce different images, and a rebuild can pull "
            "content nobody reviewed."
        ),
        remediation="Pin by digest: FROM image:tag@sha256:...",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(r"^\s*FROM\s+(?!scratch)[^\s@]+(?::[^\s@]+)?\s*(?:AS\s+\w+)?\s*$"),
        paths=("**/Dockerfile", "**/Dockerfile.*", "**/Containerfile"),
    ),
    # -- Infrastructure --------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.IAC.PUBLIC_INGRESS.001",
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
            r"(?:cidr_blocks|source_ranges|CidrIp|CidrIpv6|source_address_prefix)"
            r'\s{0,4}[=:]\s{0,4}\[?\s{0,4}"?(?:0\.0\.0\.0/0|::/0|\*|Internet)"?'
        ),
        paths=IAC_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="SUSPECT.IAC.PRIVILEGED.001",
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
    # -- Kubernetes completeness ----------------------------------------
    ConfigRule(
        rule_id="SUSPECT.K8S.RBAC_WILDCARD.001",
        title="Role grants every verb or every resource",
        message=(
            "This role grants `*` for verbs, resources or API groups. A wildcard "
            "role is not a permission set, it is the absence of one: whatever holds "
            "it can read every secret in its scope and create workloads that run "
            "anywhere the scheduler allows."
        ),
        remediation=(
            "Enumerate the verbs and resources the workload actually uses. A role "
            "that is tedious to write is one that a reviewer can check."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"(?:verbs|resources|apiGroups)\s{0,4}:\s{0,4}\[[^\]]{0,80}[\"']\*[\"']"
            r"|(?:verbs|resources|apiGroups)\s{0,4}:\s{0,20}\n\s{0,20}-\s{0,4}[\"']?\*"
        ),
        paths=IAC_PATHS + HELM_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="SUSPECT.K8S.CAPABILITIES.001",
        title="Container adds a capability that escapes the sandbox",
        message=(
            "This workload adds a Linux capability that undoes the container "
            "boundary. SYS_ADMIN is close to root on the node; SYS_PTRACE reaches "
            "into other processes; SYS_MODULE loads kernel code. Adding one of "
            "these is not hardening a container, it is opting out of one."
        ),
        remediation=(
            "Drop the capability. If the workload genuinely needs kernel-level "
            "access, run it outside the cluster where that is visible."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # Anchored on the key that grants capabilities, not on the capability
        # names alone. `ALL` is a word, and these patterns are case-insensitive,
        # so an unanchored alternation matched the phrase "nothing to drop into
        # at all" in a comment in this project's own Dockerfile. Requiring the
        # `capabilities:` / `cap_add:` context makes the match a statement about
        # what the file grants rather than about what it says.
        pattern=ConfigRule._p(
            r"(?:capabilities|cap_add|CapAdd)[\s\S]{0,200}?"
            r"\b(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|DAC_READ_SEARCH|NET_ADMIN|ALL)\b"
        ),
        paths=IAC_PATHS + HELM_PATHS + DOCKER_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001",
        title="Service-account token mounted into a workload",
        message=(
            "This workload mounts its service-account token. Any code running in "
            "the pod -- including a compromised dependency -- can read it and talk "
            "to the API server as that account."
        ),
        remediation=(
            "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API."
        ),
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(r"automountServiceAccountToken\s{0,4}:\s{0,4}true"),
        paths=IAC_PATHS + HELM_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="SUSPECT.HELM.UNTRUSTED_REPOSITORY.001",
        title="Chart depends on a chart from an unpinned or plain-HTTP repository",
        message=(
            "This chart pulls a dependency over plain HTTP, or from a repository "
            "without a version pin. Chart dependencies are rendered into the "
            "manifests that get applied to the cluster, so whoever controls that "
            "repository controls what runs."
        ),
        remediation=(
            "Use HTTPS, pin the dependency to an exact version, and prefer a "
            "repository the organisation controls or mirrors."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"repository\s{0,4}:\s{0,4}[\"']?http://"
            r"|repository\s{0,4}:\s{0,4}[\"']?(?:oci|https)://[^\n]{0,200}\n"
            r"(?:(?!\s{0,8}version\s{0,4}:)[^\n]{0,200}\n){0,3}\s{0,8}-\s"
        ),
        paths=HELM_PATHS,
    ),
    # -- CloudFormation ---------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.IAC.IAM_WILDCARD.001",
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
            r"[\"']?Action[\"']?\s{0,4}:\s{0,4}[\"']\*[\"']"
            r"|[\"']?Action[\"']?\s{0,4}:\s{0,20}\n\s{0,20}-\s{0,4}[\"']?\*"
            r"|AdministratorAccess"
            r"|[\"']?(?:iam|sts)\:\*[\"']?"
        ),
        paths=IAC_PATHS + CFN_PATHS,
        content_marker=CFN_MARKER,
    ),
    # -- Ansible ----------------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.IAC.ANSIBLE_FETCH_EXEC.001",
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
            r"(?:shell|command|raw)\s{0,4}:[^\n]{0,200}"
            r"(?:curl|wget)[^\n]{0,200}\|\s{0,4}(?:sudo\s{1,4})?(?:sh|bash|python[0-9.]{0,4})"
        ),
        paths=ANSIBLE_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.IAC.HOST_MOUNT.001",
        title="Host path mounted into a container",
        message=(
            "A host directory is mounted into the container. Mounting the container "
            "runtime's own socket is equivalent to granting root on the node, because "
            "anything that can talk to it can start a privileged container."
        ),
        remediation=(
            "Remove the mount. If the workload genuinely needs runtime access, use a "
            "brokered API with an explicit, auditable permission set."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            # The trailing group is optional so that `path: /` matches. It did
            # not: mounting the entire host root, which is strictly worse than
            # mounting /etc, was the one host path this rule ignored.
            r"/var/run/docker\.sock"
            r"|/var/run/containerd|/run/containerd/containerd\.sock"
            r"|hostPath:\s*\n\s*path:\s*[\"']?"
            r"/(?:etc|root|proc|sys|dev|boot|usr|home|var/run|var/lib/kubelet)?"
            r"[\"']?\s*(?:$|#)"
        ),
        paths=IAC_PATHS + DOCKER_PATHS,
        content_marker=K8S_MARKER,
    ),
)


class ConfigDetector(BaseDetector):
    """Inspects CI, container and infrastructure configuration."""

    id = "config"
    version = "0.2.0"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS, Category.POLICY})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        findings: list[Finding] = []
        for rule in RULES:
            if not self._applies(rule, content):
                continue
            match = rule.pattern.search(content.raw)
            if match is None:
                continue
            findings.append(self._finding(rule, unit, ctx, match, content))
        findings.extend(self._unapproved_actions(unit, ctx, content))
        return findings

    # A `uses:` reference, split into owner and the rest.
    _USES = re.compile(
        # The owner must begin with an alphanumeric, which is what an owner
        # name can begin with. Without that, `uses: ./.github/actions/x` parses
        # as an action published by an owner called ".", and a local action --
        # code already in this repository, reviewed with it -- is reported as a
        # third party.
        rb"""uses\s{0,4}:\s{0,4}["']?([A-Za-z0-9][A-Za-z0-9._-]{0,63})/([^\s"'@]{1,120})"""
    )

    def _unapproved_actions(
        self, unit: FileUnit, ctx: ScanContext, content: FileContent
    ) -> Iterable[Finding]:
        """Actions from owners the project has not accepted.

        `uses:` is not a dependency declaration. The action runs inside the job,
        with the job's token and the job's secrets, so adding one is an
        execution decision -- and unlike a dependency it is not in any lockfile,
        not in any SBOM, and not reviewed by anything downstream.

        Which owners are acceptable has no universal answer, so this reports
        nothing until the project supplies one. That is the honest behaviour
        for a policy question: a default list would be this tool's opinion
        presented as a finding.

        Local actions (`./.github/actions/...`) and reusable workflows within
        the same repository are not third-party and are not reported; the
        pattern requires an `owner/name` shape, which those do not have.
        """
        allowed = ctx.config.allowed_action_owners
        if not allowed or not any(PathGlob.matches(content.path, p) for p in CI_PATHS):
            return

        permitted = {owner.lower().rstrip("/") for owner in allowed}
        seen: set[str] = set()

        for match in self._USES.finditer(content.raw):
            owner = match.group(1).decode("utf-8", "replace")
            if owner.lower() in permitted or owner in seen:
                continue
            seen.add(owner)
            rule = ConfigRule(
                rule_id="POLICY.CI.ACTION_OWNER.001",
                title="Action from an owner outside the approved set",
                message=(
                    f"This workflow runs an action published by {owner!r}, which is "
                    f"not in the set this project approves. The action executes "
                    f"inside the job with its token and its secrets, and unlike a "
                    f"dependency it appears in no lockfile and no SBOM."
                ),
                remediation=(
                    f"Add {owner!r} to scan.allowed_action_owners if it has been "
                    f"reviewed, or replace the action with a step you control."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=Category.POLICY,
                pattern=self._USES,
                paths=CI_PATHS,
            )
            yield self._finding(rule, unit, ctx, match, content)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        """Every rule this detector can emit.

        Declared so `cordon rules list` and `rules show` are honest about what
        will run, and so configuration can disable one by id without patching
        the installed package.
        """
        return tuple(
            DeclaredRule(
                id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                detector=ConfigDetector.id,
                message=rule.message,
                remediation=rule.remediation,
            )
            for rule in RULES
        )

    @staticmethod
    def _applies(rule: ConfigRule, content: FileContent) -> bool:
        """Whether a rule should be evaluated against this file.

        Path first, because it is the cheap test and it is right for Terraform,
        Dockerfiles and workflow files, which live at conventional paths by
        definition. Content second, for the kinds that do not: a Kubernetes
        manifest is a Kubernetes manifest wherever somebody put it.
        """
        if any(PathGlob.matches(content.path, p) for p in rule.paths):
            return True
        if rule.content_marker is None:
            return False
        name = basename(content.path).lower()
        if not name.endswith((".yaml", ".yml")):
            return False
        return rule.content_marker in content.raw[:CONTENT_MARKER_BYTES]

    def _finding(
        self,
        rule: ConfigRule,
        unit: FileUnit,
        ctx: ScanContext,
        match: re.Match[bytes],
        content: FileContent,
    ) -> Finding:
        line = content.line_of(match.start())

        return Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=rule.severity,
            confidence=rule.confidence,
            message=rule.message,
            location=Location(
                path=content.path,
                line=line,
                column=content.column_of(match.start()),
                byte_start=match.start(),
                byte_end=match.end(),
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(match.group(0)),
                redaction=RedactionMode.MASKED,
                # Masked: a CI or container line is one of the likelier places
                # for a credential to sit inline, and the finding must not be
                # what copies it into a log.
                snippet=Redactor.mask(content.line_text(line).strip()[:200]),
                span=(match.start(), match.end()),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=rule.rule_id),
            risk=ctx.scorer.score(
                rule.severity,
                rule.confidence,
                ScoringContext(
                    # CI and build configuration executes before and around
                    # everything else, with the pipeline's own credentials.
                    in_install_hook=True,
                    capabilities=frozenset(rule.capabilities),
                ),
            ),
            detector=self.id,
            capabilities=rule.capabilities,
        )


__all__ = ["RULES", "ConfigDetector"]
