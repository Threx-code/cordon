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


CI_PATHS = (
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
    "**/.gitlab-ci.yml",
    "**/Jenkinsfile",
    "**/azure-pipelines.yml",
    "**/.circleci/config.yml",
    "**/bitbucket-pipelines.yml",
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
        pattern=ConfigRule._p(r"toJSON\s*\(\s*secrets\s*\)|\$\{\{\s*secrets\s*\}\}"),
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
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
        pattern=ConfigRule._p(r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh"),
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
        pattern=ConfigRule._p(r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh"),
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
        pattern=ConfigRule._p(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"'),
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
        return findings

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
        name = content.path.rpartition("/")[2].lower()
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
