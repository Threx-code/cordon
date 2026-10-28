"""The container rules: image builds that fetch and run what they cannot verify, and Kubernetes
manifests that run privileged, share the host or mount what a pod should not see.
"""

from __future__ import annotations

from cordon_scanner.detect.infra.config_paths import (
    DOCKER_PATHS,
    IAC_PATHS,
    K8S_MARKER,
    VERIFIED_FETCH,
)
from cordon_scanner.detect.infra.config_rule import ConfigRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import Category, Confidence, Severity

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

CONTAINER_RULES: tuple[ConfigRule, ...] = (
    # -- Containers ------------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.CONTAINER.FETCH_EXEC.001",
        references=(
            references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
            references.DOCKER_BUILD_BEST_PRACTICE,
        ),
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
        mitigation=VERIFIED_FETCH,
        # The same two shapes as the CI rule above. A Dockerfile that downloads
        # to a path and then runs that path is doing exactly what the piped form
        # does, written over three clauses joined by `&&`, and it produced only
        # the `low` unpinned-base note.
        pattern=ConfigRule._p(
            r"(?:curl|wget)[^\n|]{0,200}\|[ \t]{0,32}(?:sudo[ \t]{1,8})?(?:ba)?sh"
            # No backreference tying the downloaded path to the executed one.
            # It would be more precise, and the pattern validator refuses
            # backreferences for every rule pack -- engine patterns are held to
            # the same rule, which is the point of holding them to it. Fetching
            # to a file and making something executable in the same command is
            # signal enough; the pair has no innocent reading.
            r"|(?:curl|wget)[^\n]{0,200}?(?:-o|--output|-O)\s{1,4}[^\s]{1,200}"
            # Crosses newlines, deliberately and boundedly. A Dockerfile RUN
            # and a CI `run:` block are both written across backslash
            # continuations as a matter of course, so a gap that stops at the
            # first newline misses the ordinary spelling of this attack rather
            # than an evasion of it.
            r"[\s\S]{0,240}?chmod\s{1,4}(?:\+x|[0-7]?(?:[1357][0-7][0-7]|[0-7][1357][0-7]|[0-7][0-7][1357]))"
        ),
        paths=DOCKER_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="SUSPECT.CONTAINER.BUILD_SECRET.001",
        references=(references.HARDCODED_CREDENTIALS, references.DOCKER_BUILD_BEST_PRACTICE),
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
            # The keyword has to END a word. `oxsecurity/megalinter` declares
            # `ARG NPM_SECRETLINT_VERSION=13.0.5` -- the version of `secretlint`, a
            # linter -- nineteen times across its flavour Dockerfiles, and every one
            # was reported as a credential shipped in the image history. A trailing
            # `\w*` matched `SECRET` inside `SECRETLINT`, which is the same defect the
            # generic assignment rule was fixed for.
            #
            # The leading `\w{0,40}` stays loose: `CLIENTSECRET` and `GHTOKEN` are real
            # names, and requiring a separator in front would miss them.
            r"^[ \t]*(?:ARG|ENV)[ \t]+\w{0,40}"
            r"(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIALS?)"
            r"S?(?![A-Za-z])\w{0,40}"
            # And a name that is not CONFIGURATION. `langgenius/dify` sets
            # `ENV TIKTOKEN_CACHE_DIR=/app/api/.tiktoken_cache` and `open-webui` sets
            # `ARG USE_TIKTOKEN_ENCODING_NAME="cl100k_base"` -- both names carry `TOKEN`
            # because `tiktoken` is a library, and both values are a directory and an
            # encoding name. This is the same suffix list the secrets detector's
            # `names_configuration` has refused since its second release; the Docker
            # rule was the one place it had not been applied.
            r"(?<!_NAME)(?<!_DIR)(?<!_PATH)(?<!_FILE)(?<!_URL)(?<!_URI)"
            r"(?<!_TYPE)(?<!_MODE)(?<!_ENABLED)(?<!_DISABLED)(?<!_TIMEOUT)"
            r"[ \t]*="
            # And a value that is actually a value. `vimagick/dockerfiles` declares
            # `ENV HUBOT_SLACK_TOKEN=` and `ENV PASSWORD=` -- an empty variable for the
            # operator to supply at run time, which is the OPPOSITE of baking a secret
            # into a layer -- and `ENV TOKEN=00000000-0000-0000-0000-000000000000`,
            # which is the aria2 RPC placeholder.
            #
            # The name alone was the whole rule, so a Dockerfile that documented which
            # credentials it expects was reported for shipping them.
            # A trailing backslash is a line continuation, not a value. `lobehub`
            # writes `ENV KEY_VAULTS_SECRET="" \` as the first of eight variables in
            # one `ENV`, and the empty-value test above could not see past it.
            r"""[ \t]*(?!["']{0,2}[ \t]*\\?[ \t]*$)(?![-0]{6,}["' \t]*$)"""
            # And not a number or a flag. vLLM sets `ARG SCCACHE_S3_NO_CREDENTIALS=0` in
            # eight Dockerfiles -- a switch whose name ends in CREDENTIALS and whose
            # value is a zero. A credential is not `0`, `1`, `true` or `none`, and a
            # build argument holding one of those is configuring behaviour.
            r"""(?!(?:0|1|true|false|yes|no|on|off|none|null|nil)["' \t]*$)"""
            # Nor the credential word itself. `harness` sets
            # `ENV GITNESS_TOKEN_COOKIE_NAME=token`, which names the cookie a token
            # travels in; a value that is the word `token` is the word, not a token.
            # The same reasoning `PLACEHOLDER` applies to a value that reads as its own
            # name, and the secrets detector's `names_configuration` has refused the
            # `..._NAME` half of this shape since its second release.
            r"""(?!(?i:token|secret|password|passwd|passphrase|key|apikey"""
            r"""|credential|credentials|changeme|unset|empty)["' \t]*$)"""
            # Nor a variable expansion. vLLM writes
            # `ENV SCCACHE_S3_NO_CREDENTIALS=${USE_SCCACHE:+${SCCACHE_S3_NO_CREDENTIALS}}`,
            # which names two build arguments and holds nothing: whatever it ends up
            # being was supplied to the build, and `--build-arg` is the thing this rule
            # is telling people to use.
            r"""(?![$%]|["']?\$)"""
            r"""\S"""
        ),
        paths=DOCKER_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
)


KUBERNETES_RULES: tuple[ConfigRule, ...] = (
    # -- Kubernetes completeness ----------------------------------------
    ConfigRule(
        rule_id="SUSPECT.K8S.RBAC_WILDCARD.001",
        references=(references.KUBERNETES_POD_SECURITY, references.IMPROPER_ACCESS_CONTROL),
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
        # `resources` or `apiGroups`, and NOT `verbs` on its own. The message this rule
        # prints -- that whatever holds the role "can read every secret in its scope" -- is
        # true of every resource and of every API group, and false of every verb on one
        # named resource.
        #
        # `halo-dev/halo` declares fourteen role templates of the form
        # `apiGroups: ["content.halo.run"], resources: ["tags"], verbs: ["*"]`. That is
        # full control of tags, which is what a `manage-tags` role is FOR, and it was
        # reported at the same severity as `cluster-admin`. It is also what this rule's own
        # remediation asks for: enumerate the resources, and then every verb on them is a
        # choice somebody made deliberately.
        #
        # Nothing real is lost, because a genuine wildcard grant wildcards one of the other
        # two as well. `argo-cd`'s application controller asks for `apiGroups: ['*']`,
        # `resources: ['*']` and `verbs: ['*']`, and Kubernetes' own cloud-node-controller
        # for `apiGroups: ["*"]`, `resources: ["*"]` and `verbs: [list]`. Both still report.
        pattern=ConfigRule._p(
            r"(?:resources|apiGroups)[ \t]{0,32}:[ \t]{0,32}\[[^\]]{0,80}[\"']\*[\"']"
            # `\r?\n`, not `\n`. This crosses from the key to the block-sequence
            # entry below it, and `[ \t]` does not contain the carriage return a
            # file written on Windows puts there -- so `argo-cd`'s cluster-admin
            # role, which spells its wildcards in the block form, was not matched
            # at all on that platform. The negated `[^\n]` classes elsewhere in
            # this file are unaffected: they absorb the `\r` on their own.
            r"|(?:resources|apiGroups)[ \t]{0,32}:[ \t]{0,32}\r?\n[ \t]{0,40}-[ \t]{0,32}[\"']?\*"
        ),
        # And not an admission webhook or policy, whose `rules:` say which resources to
        # INSPECT. See `ConfigRule.foreign_kind`.
        foreign_kind=ConfigRule._p(
            r"^kind:[ \t]*(?:Validating|Mutating)(?:WebhookConfiguration"
            r"|AdmissionPolicy(?:Binding)?)[ \t]*$"
        ),
        paths=IAC_PATHS + HELM_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="SUSPECT.K8S.CAPABILITIES.001",
        references=(
            references.KUBERNETES_POD_SECURITY,
            references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
        ),
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
        # `add` is required between the key and the capability, because `drop` is
        # the other thing that appears there and it means the opposite.
        #
        # `capabilities: drop: [ALL]` is the most hardened setting a container can
        # have, and it was reported as "adds a capability that escapes the sandbox" --
        # the rule telling a project that its best practice was an escape. Every
        # Helm chart that documents the hardened form in a comment got it, and so
        # would every chart that actually applies it.
        #
        # `cap_add` and `CapAdd` already say `add` in the key, so they stand alone.
        pattern=ConfigRule._p(
            # `add` has to be the capabilities' own key, and nothing between it and the
            # capability name may be a `drop`.
            #
            # Argo CD ships `manifests/ha/base/redis-ha/overlays/
            # deployment-containers-securityContext.yaml`, a kustomize patch whose whole
            # purpose is to HARDEN the container:
            #
            #     - op: add
            #       path: /spec/template/spec/containers/0/securityContext
            #       value:
            #         capabilities:
            #           drop:
            #           - ALL
            #
            # A bare `\badd\b` matched the patch operation, `ALL` matched the dropped
            # list, and cordon reported the remediation as the finding. Two of Argo CD's
            # fifteen remaining findings were that file, and it is the worst shape a
            # security tool can have: telling a project that hardening is a weakness
            # teaches them the tool cannot read YAML.
            #
            # `drop: [ALL]` followed by `add: [NET_ADMIN]` is still reported, because it
            # does add NET_ADMIN -- there is a test for that.
            r"(?m)(?:capabilities[\s\S]{0,80}?"
            r"(?:^[ \t]*-?[ \t]*add[ \t]*:|add[ \t]*:[ \t]*\[)"
            r"|cap_add|CapAdd)"
            r"(?:(?!\bdrop\b)[\s\S]){0,200}?"
            r"\b(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|DAC_READ_SEARCH|ALL)\b"
        ),
        paths=IAC_PATHS + HELM_PATHS + DOCKER_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="POLICY.K8S.NET_ADMIN.001",
        references=(
            references.KUBERNETES_POD_SECURITY,
            references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
        ),
        title="Container adds network-administration capability",
        message=(
            "This workload adds NET_ADMIN or NET_RAW. That lets it reconfigure routing "
            "and read raw packets, and with host networking that reaches the host's "
            "interfaces. It does not escape the container the way SYS_ADMIN does."
        ),
        remediation=(
            "Confirm the workload needs to configure networking. If it does, keep it off "
            "host networking so the capability stays inside its own namespace."
        ),
        # MEDIUM, and split out of `SUSPECT.K8S.CAPABILITIES.001` where it sat beside
        # SYS_ADMIN. That rule's own message names SYS_ADMIN, SYS_PTRACE and SYS_MODULE
        # and says adding one "is not hardening a container, it is opting out of one" --
        # true of those three and not of NET_ADMIN, which configures the container's own
        # network namespace. That is what every VPN, every WireGuard sidecar and every
        # `tun`-based tool exists to do.
        #
        # Measured: six of the corpus repositories carrying three findings or fewer were
        # this, and every one needed it -- `angristan/openvpn-install`, `dockur/windows`,
        # `winapps`, `anything-llm`, and two ComfyUI ROCm compose files. A HIGH finding
        # whose remediation reads "do not be a VPN" is one a project can only suppress.
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(
            r"(?m)(?:capabilities[\s\S]{0,80}?"
            r"(?:^[ \t]*-?[ \t]*add[ \t]*:|add[ \t]*:[ \t]*\[)"
            r"|cap_add|CapAdd)"
            r"(?:(?!\bdrop\b)[\s\S]){0,200}?"
            r"\b(?:NET_ADMIN|NET_RAW)\b"
        ),
        paths=IAC_PATHS + HELM_PATHS + DOCKER_PATHS,
        content_marker=K8S_MARKER,
    ),
    ConfigRule(
        rule_id="POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001",
        references=(references.KUBERNETES_POD_SECURITY, references.EXPOSED_RESOURCE),
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
        pattern=ConfigRule._p(r"automountServiceAccountToken[ \t]{0,32}:[ \t]{0,32}true"),
        paths=IAC_PATHS + HELM_PATHS,
        content_marker=K8S_MARKER,
    ),
)


__all__ = ["CONTAINER_RULES", "HELM_PATHS", "KUBERNETES_RULES"]
