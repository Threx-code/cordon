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

import functools
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
from cordon_scanner.detect.secrets import (
    FIXTURE_CEILING,
    RULE_MATERIAL_CEILING,
    is_generated_artefact,
    is_test_material,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit


_BOM_ANCHOR = "(?:^(?:\ufeff)?)"
"""What `^` becomes: start of line, then an optional byte-order mark.

Built from the character itself rather than an escape, because `re.sub`
reads its replacement as a template and `\\u` is not a template escape.
"""


_ADMIN_PORT = (
    r"(?:from_port|to_port|FromPort|ToPort|destination_port_range|port|Port)"
    r'[ \t]{0,32}[=:][ \t]{0,32}\[?[ \t]{0,32}"?'
    r"(?:22|23|135|139|445|1433|1521|2375|2376|2379|2380|3306|3389|5432|5900"
    r"|5984|6379|6443|8020|9000|9200|11211|27017|0|\*|-1)\b"
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


@dataclass(frozen=True, slots=True)
class ConfigRule:
    #: `$` in a line-oriented pattern, rewritten to tolerate a carriage return.
    #:
    #: `re`'s `$` under `MULTILINE` matches before a `\n` and does not step over the
    #: `\r` in front of it, so every pattern anchored at end of line silently stops
    #: matching on a file written on Windows. `kind: ValidatingWebhookConfiguration`
    #: is the case that found it: the `foreign_kind` test below did not match, the
    #: suppression it gates never fired, and an admission webhook -- which grants no
    #: permission at all -- was reported as a wildcard RBAC grant. Every Kubernetes
    #: manifest with CRLF endings was affected, which is most of them in a repository
    #: written on Windows.
    #:
    #: Not inside a character class, and not an escaped `\$`: `(?![$%]|["\']?\$)`
    #: below means both spellings appear in this file.
    _LINE_END = re.compile(r"(?<!\\)(?<!\[)\$(?!\])")

    #: `^` in the same patterns, rewritten to step over a byte-order mark.
    #:
    #: These rules match `content.raw`, and text decoding is where the mark is
    #: normally dropped -- so a `Dockerfile` written by a Windows editor carries
    #: three bytes in front of `FROM`, `^[ \t]*FROM` does not match, and
    #: `POLICY.CONTAINER.UNPINNED_BASE.001` is simply not reported. The optional
    #: group only ever matches at the start of the file, because that is the only
    #: place a mark can be.
    #:
    #: Fifteen real anchors here against thirty-three `[^...]` negations, and no
    #: caret sits anywhere else in a class, so the guard below is sufficient.
    _LINE_START = re.compile(r"(?<!\\)(?<!\[)\^")

    @staticmethod
    def _p(pattern: str) -> re.Pattern[bytes]:
        anchored = ConfigRule._LINE_END.sub(r"(?=\r?$)", pattern)
        anchored = ConfigRule._LINE_START.sub(lambda _: _BOM_ANCHOR, anchored)
        return re.compile(anchored.encode("utf-8"), re.MULTILINE | re.IGNORECASE)

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

    foreign_kind: re.Pattern[bytes] | None = None
    """A declaration, in the same YAML document, that this rule is about something else.

    Distinct from `mitigation` below, and the distinction is the whole point: a
    mitigation says the weakness is controlled and lowers the severity. This says the
    weakness is not there -- the rule read a key that means something different in this
    kind of document, and the finding is false rather than mild.

    `SUSPECT.K8S.RBAC_WILDCARD.001` is the case. It matches `resources: ["*"]`, and a
    `ValidatingWebhookConfiguration` has exactly that key with exactly that value to say
    which resources the webhook inspects. `istio` ships four of them -- and its
    `ValidatingAdmissionPolicy` narrows `apiGroups` to its own CRDs and then says
    `resources: ["*"]` WITHIN those groups, which is the opposite of a wildcard grant.
    Neither document grants any permission at all.

    Scoped to the YAML document rather than the file, because a bundle holds both:
    `argo-cd`'s `manifests/install.yaml` carries its ClusterRoles and its webhook
    configuration in one stream, and a file-level test would suppress the real finding
    along with the false one. See `_document_window`."""

    mitigation: re.Pattern[bytes] | None = None
    """Evidence, near the match, that the weakness this rule names is controlled.

    A rule reports a shape. Sometimes the same file also contains the thing that
    makes the shape safe, and reporting both at the same severity tells a project
    that doing it correctly and doing it carelessly are equally bad -- which is how a
    rule stops being read.

    The case that prompted it: `SUSPECT.CONTAINER.FETCH_EXEC.001` at HIGH on
    Elasticsearch's Dockerfile, which pins a release URL and then runs
    `echo "${tini_sum}  /tmp/tini" | sha256sum -c -`. Two lines further into the same
    file as Vault's `curl -sL https://deb.nodesource.com/setup_20.x | bash -`, which
    verifies nothing. The first is the remediation this rule asks for. Both got HIGH.

    Lowers the severity by one step rather than suppressing, because a verified fetch
    is still a fetch: the bytes are pinned, and the fact that the build reaches the
    network at all is worth a line in the report.
    """

    in_shell: bool = False
    """Only report a match that lands in something a shell will parse.

    For a rule whose claim is "interpolated into a script", this is the claim. The
    alternative was a list of keys whose values never reach a shell, and the list
    could only ever be as long as the last repository somebody measured:
    `concurrency.group` was the first, `embed-title` on a Discord-notify action was
    the next, and React produced three of those.

    See `_shell_regions`, which answers the question from the document's own shape
    rather than from a vocabulary."""

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


#: Ways a build proves the bytes it fetched are the bytes it meant to fetch.
#:
#: Checksum verification, signature verification, or a transparency-log check.
#: Deliberately not "the URL contains a version number": pinning a version says what
#: was asked for and nothing about what arrived, which is the distinction this rule
#: exists to draw in the first place.
TRUSTED_ACTOR_GATE = re.compile(
    rb"(?i)if:[^\n]{0,300}?(?:github\.(?:actor|triggering_actor)"
    rb"|event\.pull_request\.user\.login|event\.(?:issue|comment)\.user\.login)"
    rb"[^\n]{0,80}?(?:==|!=|contains\(|in[ \t]*\()[^\n]{0,120}?['\"\[]"
)
"""A job that only runs for a NAMED actor.

`discourse/discourse` checks a pull request body under `pull_request_target`, checks out
the head, and gates the whole job on
`if: github.event.pull_request.user.login == 'dependabot[bot]'`. A login cannot be
spoofed and dependabot does not take contributions, so the head it checks out is
dependabot's own -- the condition is the control, and it is the one GitHub's own
documentation recommends for exactly this case.

A step down rather than silence, for the reason every mitigation here is: the trigger
plus the checkout is still the shape, and a gate somebody widens later stops being one.
The unconditional form keeps its severity, which is what the rule is named for.
"""

VERIFIED_FETCH = re.compile(
    rb"(?i)(?:"
    # A pinned reference, as well as a verified one. The two are not the same
    # strength and they are both answers to the same question: what the build will
    # run is decided before the build, not by whoever controls a host today.
    #
    # `dotnet/dotnet-docker` produced 34 findings at HIGH, every one this line in
    # the official .NET base images:
    #
    #     curl --output /usr/bin/chisel-wrapper \
    #       https://raw.githubusercontent.com/canonical/rocks-toolbox/v1.2.0/chisel-wrapper
    #     chmod 755 /usr/bin/chisel-wrapper
    #
    # Downloading a released binary and making it executable is how a container image
    # installs a tool, and `vimagick/dockerfiles` supplied the same shape for cadvisor,
    # confd, the Home Assistant CLI and yt-dlp. The rule's comment claimed the pair
    # "has no innocent reading", and the measurement disagreed: 291 findings across 122
    # of 1,487 repositories.
    #
    # A step down rather than silence, and the unpinned forms keep their severity --
    # `curl https://sh.rustup.rs | sh` and `curl https://bootstrap.saltstack.com | bash`
    # are in the same corpus and are exactly what this rule is for.
    rb"/v?\d+\.\d+(?:\.\d+)?/"
    # A version supplied by a VARIABLE, which is how a pipeline writes the same pin.
    # `FuelLabs/fuels-rs` downloads
    # `.../sway/releases/download/v${{ env.FORC_VERSION }}/forc-binaries-linux_amd64.tar.gz`
    # and the `/releases/download/[^/\s]{1,80}/` alternative below could not see it,
    # because a GitHub Actions expression has SPACES inside its braces and `[^/\s]`
    # refuses them. The version is pinned; it is pinned one line further up, in `env`.
    #
    # The variable has to NAME a version. `${{ github.event.pull_request.head.ref }}`
    # in a download path is attacker-controlled and is the opposite of a pin, so an
    # expression on its own is not enough.
    rb"|\$\{\{[^}]{0,60}(?:VERSION|TAG|RELEASE|REVISION|version|tag|release)[^}]{0,40}\}\}"
    # `MAJOR`, `MINOR` and `VER` as well as `VERSION`. `linuxserver` and half a dozen
    # others write `setup_${NODE_MAJOR}.x`, which is the same pin under the name the
    # NodeSource documentation uses.
    rb"|\$\{?(?:[A-Z_]{0,30})(?:VERSION|VER|MAJOR|MINOR|TAG|RELEASE|REVISION)[A-Z_]{0,30}\}?"
    # A version TOKEN that is not bounded by slashes. `curl -fsSL https://bun.com/install
    # | bash -s "bun-v1.3.14"` puts the pin in the argument rather than the path, and
    # `sccache-v0.4.1-${RUNNER_ARCH}` puts it in the filename. The leading separator is
    # what keeps this from matching a version inside an opaque token.
    rb"|[-@_ \"']v?\d+\.\d+\.\d+\b"
    # A checksum computed from what was fetched. The `echo ... | sha256sum` form was
    # here; `ACTUAL=$(curl ... | sha256sum | cut -d\' \' -f1)` is the same verification
    # written the other way round, and Puppeteer's Chrome-for-Testing download does it.
    rb"|\|[ \t]*sha(?:256|512)sum"
    rb"|/releases/download/[^/\s]{1,80}/"
    rb"|/archive/refs/tags/"
    rb"|/refs/tags/"
    rb"|@[0-9a-f]{40}\b"
    rb"|[?&](?:ref|sha|commit)=[0-9a-f]{7,40}\b"
    rb"|sha(?:1|256|512)sum[ \t]+(?:-c|--check)"
    rb"|shasum[ \t]+-a[ \t]*\d+[^\n]{0,80}(?:-c|--check)"
    rb"|md5sum[ \t]+(?:-c|--check)"
    rb"|gpg[^\n]{0,80}--verify"
    rb"|cosign[ \t]+verify"
    rb"|minisign[ \t]+-V"
    rb"|--checksum[= \t]"
    rb"|CHECKSUM[ \t]*="
    rb"|_sum[ \t]*="
    rb"|echo[^\n]{0,120}\|[ \t]*sha(?:256|512)sum"
    rb")"
)


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

GITHUB_WORKFLOW_PATHS = (
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
)
"""Workflow files only.

Several rules below are about GitHub's trigger, runner and token model, and a
`.gitlab-ci.yml` has none of it. Matching them against every file in `CI_PATHS`
would report a shape that cannot exist in the file being reported.
"""

FORK_GUARD = re.compile(
    rb"(?i)if:[^\n]{0,300}?github\.event\.pull_request\.head\.repo\.(?:full_name|fork)"
)
"""A job that only runs when the pull request came from this repository.

`head.repo.full_name == github.repository` is the documented way to keep a
fork's code off a privileged or persistent runner, and a workflow carrying it
has already made the decision the rule exists to ask about. A step down rather
than silence: the guard is one edit from being widened, and the job still runs
contributor code when somebody widens it.
"""

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

# -- Build systems (Domain 4) -----------------------------------------------
#
# `capabilities-build.yaml` already gives Gradle, Maven, CMake and MSBuild
# source a behavioural spawn/exec signal, consumed by the general-purpose
# composites in `composites.yaml`; Make inherits the shell capability set
# instead (see that file's own note on why). What neither covers is the
# declarative, syntax-level risk with no capability signal to key off: a
# Makefile recipe piping a download to a shell, a Gradle or Maven coordinate
# that resolves to whatever is newest today rather than a fixed version, and
# a CMake or MSBuild fetch with nothing verifying what it downloaded. These
# rules are that layer -- the coverage matrix's Domain 4 previously shipped
# with none.

MAKE_PATHS = (
    "**/Makefile",
    "**/makefile",
    "**/GNUmakefile",
    "**/*.mk",
)

CMAKE_PATHS = (
    "**/CMakeLists.txt",
    "**/*.cmake",
)

MSBUILD_PATHS = (
    "**/*.csproj",
    "**/*.vcxproj",
    "**/*.targets",
    "**/*.props",
)

GRADLE_MAVEN_PATHS = (
    "**/build.gradle",
    "**/build.gradle.kts",
    "**/pom.xml",
)


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
        # The whole context, and only the whole context.
        #
        # A *named* secret near a network call was matched here too, and that is
        # a different claim wearing this one's severity: `env: TOKEN: ${{
        # secrets.NPM_TOKEN }}` beside a `curl` is how every pipeline publishes
        # anything. It produced twenty critical findings across Node's, ESLint's
        # and webpack's release workflows -- a Discord announcement, a Netlify
        # build hook, a Jenkins trigger. That shape moved to
        # `SUSPECT.CI.SECRET_EGRESS.001`, which says what was actually observed.
        #
        # What is left has no benign reading. Serialising every secret the job
        # can reach into one string is not how anything legitimate passes a
        # credential, and the message's claim is true of exactly this.
        pattern=ConfigRule._p(
            r"toJSON[ \t]{0,32}\([ \t]{0,32}secrets[ \t]{0,32}\)"
            r"|\$\{\{[ \t]{0,32}secrets[ \t]{0,32}\}\}"
        ),
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.SECRET_EGRESS.001",
        title="Pipeline step reads a secret and sends data off the runner",
        message=(
            "A named secret and a network call appear in the same step. That is "
            "how a pipeline publishes a release and how one exfiltrates a token, "
            "and the two are the same shape from here: what separates them is "
            "where the data goes, which this cannot decide. Masking is not a "
            "control on it -- masking hides a value in the log and does nothing "
            "about its destination."
        ),
        remediation=(
            "Confirm the destination is one this project owns. A secret that a "
            "step both reads and transmits has left the boundary the CI system "
            "was protecting it inside, whether or not that was intended."
        ),
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # Suspicious rather than malicious, and that is the whole point of
        # splitting it out of `MALWARE.CI.SECRET_EXFIL.001`. As a critical
        # malicious finding this fired on Node's Jenkins trigger, ESLint's
        # Netlify build hook and webpack's Discord release announcement --
        # twenty of them, every one a project publishing something with its own
        # credential. The observation is real and worth a reviewer's eye; the
        # conclusion it was drawing was not available from what it saw.
        #
        # Every CI system's own syntax, because each has users who assume
        # masking is a control: GitHub interpolates `${{ secrets.NAME }}`,
        # GitLab exposes `$NAME`, Jenkins binds with `credentials()` or
        # `withCredentials`, Azure uses `$(Name)`. Paired with an egress verb
        # inside a bounded window, so a pipeline that uses a secret in one job
        # and calls curl in an unrelated one is not caught.
        # `secrets.GITHUB_TOKEN` is excluded, and that single exclusion is most of
        # what this rule needed.
        #
        # It is not a secret the repository holds. GitHub mints it per job, scopes it
        # to that repository, and revokes it when the job ends -- there is nothing to
        # rotate and nothing to leak beyond the job's own lifetime and permissions.
        # Using it with `curl` or `gh` against the GitHub API is the most common thing
        # in all of CI.
        #
        # Measured across 535 repositories this rule fired in 31% of them, and every
        # sampled finding was an ordinary workflow: `release-milestone.yml`,
        # `upload-test-stats.yml`, `notify-on-merge.yml`, `label_stale_issues.yml`,
        # `send_release_notification.yml`. The rule's own notes record that it was
        # split out of the critical rule because it was firing on "every pipeline
        # publishing something with its own credential", and it was still doing
        # exactly that one severity down.
        #
        # The severity drops to MEDIUM for what remains, for the reason the message
        # itself gives: what separates publishing from exfiltration is where the data
        # goes, and this cannot decide that. A finding worth a reviewer's eye is not a
        # finding worth failing a build, and the shape is far too common to block on.
        # `MALWARE.CI.SECRET_EXFIL.001` still reports a serialised secret context at
        # CRITICAL, and `SUSPECT.CI.FETCH_EXEC.001` still reports fetch-and-run.
        severity=Severity.MEDIUM,
        pattern=ConfigRule._p(
            _near(
                r"(?:\$\{\{[ \t]{0,32}secrets\.(?!GITHUB_TOKEN\b)\w{1,64}[^\n]{0,80}\}\}"
                r"|credentials[ \t]{0,32}\(|withCredentials\b"
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
            # Not a line that is only `KEY: ${{ ... }}`.
            #
            # That shape is the remediation this rule recommends. GitHub's own
            # guidance is to bind the untrusted value to an environment
            # variable and reference `"$VAR"` from the script, so the shell
            # parses the line before the value reaches it -- and the rule was
            # firing on exactly that, seventy-two times across Django's,
            # Grafana's and Home Assistant's workflows, telling projects that
            # had done the right thing that they had not.
            #
            # What remains is interpolation into something: a `run:` script, a
            # quoted string with other text around it, a JSON payload. That is
            # where the value becomes part of the command rather than an
            # argument to it.
            # `[ \t\r]` rather than `[ \t]` before the anchor: a repository
            # with CRLF endings leaves a carriage return there, and without it
            # the exemption silently stopped applying to every workflow written
            # on Windows -- which is the half of the world most likely to have
            # them.
            r"(?m)^(?![ \t]{0,64}[A-Za-z_][A-Za-z0-9_.-]{0,64}:"
            r"[ \t]{0,8}\$\{\{[^\n]{0,200}\}\}[ \t\r]{0,8}$)"
            # And not a key whose value never reaches a shell. The rule's own message
            # is "interpolated directly into a script", and these are not scripts.
            #
            # `concurrency.group` is the case that exposed it: DuckDB writes
            # `group: osx-${{ github.workflow }}-${{ github.ref }}-${{ github.head_ref
            # || '' }}-...` in ten workflows, which is the documented way to scope
            # cancellation per branch. A group name is a string GitHub compares for
            # equality. There is no shell, so there is nothing to inject into, and the
            # existing exemption did not apply because the line has other text around
            # the expression.
            #
            # `name`, `runs-on`, `container`, `image` and `environment` are the same:
            # GitHub consumes the value itself rather than handing it to an
            # interpreter. `key` and `restore-keys` reach a cache rather than a shell,
            # and cache poisoning is `SUSPECT.CI.ARTIFACT_POISONING.001`.
            r"(?![ \t]{0,64}(?:group|name|runs-on|container|image|environment|url"
            r"|key|restore-keys|path|tags|labels|timeout-minutes|concurrency"
            r"|cancel-in-progress|if)[ \t]{0,8}:)"
            r"[^\n]{0,300}"
            r"\$\{\{[ \t]{0,32}github\.(?:event\.(?:issue|pull_request|comment|"
            # `user.login` is NOT here. GitHub validates a login to alphanumerics and
            # single hyphens, so it cannot carry a semicolon, a backtick or a quote --
            # there is nothing to inject. A title or a body can carry anything.
            #
            # nlohmann writes `echo ${{ github.event.pull_request.user.login }} >
            # ./pr/author` and Astro writes `--body "Hello @${{ github.event.issue.user
            # .login }}"`, and both were the only blocking finding in their repository.
            r"discussion|review)\.(?:title|body)"
            r"|event\.head_commit\.message|head_ref)"
        ),
        # The claim is "interpolated into a script", so the match has to land in
        # something an interpreter parses. That replaces the list of keys whose values
        # never reach a shell, which could only ever be as long as the last repository
        # somebody measured: `concurrency.group` in DuckDB was the first, and React
        # writes `embed-title: '#${{ github.event.number }} ...'` on a Discord-notify
        # action three times, which is a string posted to a chat room.
        #
        # 216 findings across 91 of the 1,427 repositories measured.
        in_shell=True,
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
        # THREE halves, and the third is the one that was missing: the message claims
        # the workflow "runs contributor code", and `pull_request_target` on its own
        # does not. The trigger exists so that a workflow can comment, label or triage
        # with the base repository's token, and `actions/checkout` defaults to the BASE
        # ref there -- which is why the trigger is safe when nothing checks out the head.
        #
        # `apache/beam` produced 71 findings, one per workflow: every one of its post-
        # commit suites is triggered by `pull_request_target` so that a committer can
        # run it on a contributor's branch, and every one uses `actions/cache` and
        # `actions/upload-artifact`. None of them checks out the pull request head.
        #
        # This is the same correction `SUSPECT.CI.PR_TARGET.001` above already carries,
        # made for the same reason on the rule next to it: what is exploitable is
        # checking out the head and then running it.
        pattern=ConfigRule._p(
            # A trigger KEY, for the reason `SUSPECT.CI.PR_TARGET.001` above records:
            # `servo/servo` excludes the trigger in an `if:` and was reported for it.
            r"(?:^[ \t]{0,8}pull_request_target[ \t]*:"
            r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bpull_request_target\b"
            r"|^[ \t]{0,8}-[ \t]*pull_request_target[ \t]*$)[\s\S]{0,4000}?"
            r"ref:[^\n]{0,120}(?:github\.event\.pull_request\.(?:head|merge_commit_sha)"
            r"|github\.head_ref)"
            r"[\s\S]{0,4000}?"
            r"(?:actions/upload-artifact|actions/cache|save-cache|restore-cache)"
        ),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.PR_TARGET.001",
        title="Workflow uses pull_request_target and checks out the pull request head",
        message=(
            "pull_request_target runs with a writable token and the base "
            "repository's secrets, and this workflow checks out the pull request "
            "head in that context. Contributor code then executes with full write "
            "access to the repository and the ability to read every secret the job "
            "can reach. This is the most commonly exploited misconfiguration in CI."
        ),
        remediation=(
            "Use pull_request for anything that runs contributor code. If "
            "pull_request_target is required to comment or label, do not check out "
            "the head ref in the same job."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # Both halves, because the message claims both and the pattern was the
        # trigger alone: `pull_request_target`, anywhere in any workflow.
        #
        # `spf13/cobra` was reported at HIGH for a labeller workflow with no
        # checkout step in it at all -- `actions/labeler` and `pull-requests:
        # write`, which is the pattern GitHub's own documentation recommends for
        # labelling a pull request. The rule's title said "with an explicit
        # checkout", its message said "this workflow also checks out a specific
        # ref", and nothing checked.
        #
        # A BARE checkout under `pull_request_target` is not the bug either:
        # `actions/checkout` defaults to the base ref there, which is the whole
        # reason the trigger exists. What is exploitable is checking out the pull
        # request HEAD and then running it, so the ref is what this looks for.
        #
        # Window set wider than `_near`'s default: the trigger is at the top of the
        # file and the checkout is inside a job, with `permissions`, `jobs`,
        # `runs-on` and often several earlier steps between them.
        pattern=ConfigRule._p(
            _near(
                # The trigger, as a YAML KEY. `servo/servo` writes
                # `if: github.event_name != 'pull_request_target'` -- a guard that the
                # event is NOT that one -- and the rule matched the string inside it,
                # then found a head checkout elsewhere in the file and reported the
                # workflow for the trigger it explicitly excludes.
                #
                # A trigger is a key: `pull_request_target:` at the start of a line, or
                # the inline `on: pull_request_target` and `on: [pull_request_target]`
                # forms. A quoted occurrence in an expression is a comparison.
                r"(?:^[ \t]{0,8}pull_request_target[ \t]*:"
                r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bpull_request_target\b"
                r"|^[ \t]{0,8}-[ \t]*pull_request_target[ \t]*$)",
                r"ref:[^\n]{0,120}(?:github\.event\.pull_request\.(?:head|merge_commit_sha)"
                r"|github\.head_ref)",
                window=4000,
            )
        ),
        # A job gated on a named actor. See `TRUSTED_ACTOR_GATE`.
        mitigation=TRUSTED_ACTOR_GATE,
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
        # The same mitigation the container rule carries, for the same reason and by
        # the same argument: what runs is decided before the build rather than by
        # whoever controls a host today. Without it this rule reported `uv`'s own
        # `build-dev-binaries.yml`, nvm's installer test, and Rust's CI bootstrap at
        # HIGH for downloading a pinned release -- 50 findings across 27 of the first
        # 261 repositories measured.
        #
        # A step down, not silence. A pipe from an unpinned URL into a shell keeps its
        # severity, which is the shape the rule is named for.
        mitigation=VERIFIED_FETCH,
        # Two shapes, because there are two ways to run what you fetched. The
        # pipe is the famous one; downloading to a path and then executing that
        # path is the same act written over three clauses, and it produced only
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
        # Inside something an interpreter runs. The rule's own message is "a pipeline
        # STEP downloads something and runs it", and without this it matched any
        # occurrence anywhere in a workflow file: `cloudflare/workers-sdk` documents its
        # own installer in an action input --
        #
        #     description: 'How OLD gets installed. Supported: installer-script
        #                   (curl | bash one-liner) ...'
        #
        # -- which is help text for a form field. `in_shell` is the condition the
        # expression-injection rule beside it already uses, and `run:`, `script:`, `cmd:`
        # and `entrypoint:` are the keys that hand a value to an interpreter.
        in_shell=True,
        paths=CI_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.SELF_HOSTED_FORK.001",
        title="A fork's pull request runs on a self-hosted runner",
        message=(
            "This workflow is triggered by a pull request and runs on a self-hosted "
            "runner. A fork's code then executes on hardware you own and reuse: the "
            "runner keeps its filesystem, its caches, its credentials and whatever a "
            "previous job left behind, so one pull request can plant something the "
            "next job picks up. A GitHub-hosted runner is destroyed after the job."
        ),
        remediation=(
            "Run fork pull requests on GitHub-hosted runners, or gate the job on "
            "github.event.pull_request.head.repo.full_name == github.repository so "
            "that only branches in this repository reach the self-hosted one."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # The trigger as a KEY, in the three spellings a workflow uses. A quoted
        # occurrence inside an `if:` is a comparison rather than a trigger, which
        # is the correction the two rules above already carry.
        pattern=ConfigRule._p(
            _near(
                r"(?:^[ \t]{0,8}pull_request(?:_target)?[ \t]*:"
                r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bpull_request(?:_target)?\b"
                r"|^[ \t]{0,8}-[ \t]*pull_request(?:_target)?[ \t]*$)",
                r"runs-on:[^\n]{0,200}self-hosted",
                window=4000,
            )
        ),
        mitigation=FORK_GUARD,
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.WORKFLOW_RUN_CHECKOUT.001",
        title="workflow_run checks out the commit that triggered it",
        message=(
            "`workflow_run` runs in the base repository's context -- a writable token "
            "and every secret -- and this workflow checks out the commit that "
            "triggered it. That commit is whatever the earlier, unprivileged workflow "
            "was running, which for a fork's pull request is contributor code. It is "
            "`pull_request_target` by another name, with the same consequence."
        ),
        remediation=(
            "Download what the first workflow produced as an artefact and treat it as "
            "data. Do not check out or execute the triggering commit from a "
            "`workflow_run` job."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            _near(
                r"(?:^[ \t]{0,8}workflow_run[ \t]*:"
                r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bworkflow_run\b"
                r"|^[ \t]{0,8}-[ \t]*workflow_run[ \t]*$)",
                r"ref:[^\n]{0,160}github\.event\.workflow_run\."
                r"(?:head_sha|head_branch|head_commit)",
                window=4000,
            )
        ),
        mitigation=TRUSTED_ACTOR_GATE,
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.CACHE_POISONING.001",
        title="A publishing workflow restores a cache an untrusted run can write",
        message=(
            "This workflow publishes a release artefact and also restores a cache. A "
            "cache entry written on the default branch is readable by every branch, "
            "and one written by a pull request is restorable through a prefix key -- "
            "so somebody who can run CI can decide what the release build compiles "
            "against, without changing anything in the repository."
        ),
        remediation=(
            "Do not restore caches in the job that publishes. Build the artefact in a "
            "job with no cache, or make the cache key cover every input that decides "
            "what is published."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            _near(
                r"(?:npm[ \t]+publish|yarn[ \t]+publish|pnpm[ \t]+publish"
                r"|twine[ \t]+upload|pypa/gh-action-pypi-publish"
                r"|cargo[ \t]+publish|gem[ \t]+push|docker[ \t]+push"
                r"|gh[ \t]+release[ \t]+create|softprops/action-gh-release)",
                r"(?:actions/cache|restore-keys[ \t]*:)",
                window=6000,
            )
        ),
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.CI.WRITE_ALL_PERMISSIONS.001",
        title="Workflow token is granted every write scope",
        message=(
            "`permissions: write-all` gives the job's token write access to every "
            "scope the repository has -- contents, packages, deployments, actions, "
            "security events. Everything the job runs, including every third-party "
            "action in it, can use all of it."
        ),
        remediation=(
            "Declare the scopes the job needs and nothing else, starting from "
            "`permissions: {}` and adding one at a time."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(r"^[ \t]{0,16}permissions[ \t]*:[ \t]*write-all[ \t]*$"),
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.CI.UNPINNED_REUSABLE_WORKFLOW.001",
        title="Reusable workflow called by a mutable ref",
        message=(
            "A reusable workflow from another repository is called by branch or tag. "
            "The whole workflow -- every step and every action inside it -- is "
            "whatever that ref points at when the job runs, and it executes with this "
            "repository's token and the secrets the caller passes it."
        ),
        remediation=(
            "Pin the call to a full commit SHA and record the version in a trailing "
            "comment: uses: owner/repo/.github/workflows/build.yml@<sha>  # v2.1.0"
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        # The action rule above cannot match this shape: its pattern expects
        # `owner/repo@ref`, and a reusable workflow carries the file path between
        # the two.
        pattern=ConfigRule._p(
            r"uses:\s*(?!\./)[\w.\-]+/[\w.\-]+/[^\s@]{1,120}\.ya?ml"
            r"@(?!\b[0-9a-f]{40}\b)[\w.\-]+"
        ),
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.GITLAB_INJECTION.001",
        title="GitLab job interpolates a contributor-controlled variable into a script",
        message=(
            "A predefined variable an outside contributor controls -- a commit title, "
            "a branch name, a merge request title -- is expanded by the shell that "
            "runs this job. The value is not an argument to the command, it is part "
            "of the line, so a title containing a semicolon or a backtick runs "
            "whatever follows with the job's token and the project's variables."
        ),
        remediation=(
            "Bind the value with `variables:` and quote every use, or pass it to the "
            "command through a file. It must not be expanded into the text of a "
            "script line."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"\$\{?(?:CI_COMMIT_(?:TITLE|MESSAGE|DESCRIPTION|REF_NAME|BRANCH|TAG|AUTHOR)"
            r"|CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|SOURCE_PROJECT_PATH)"
            r"|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\b"
        ),
        # The claim is "expanded by the shell that runs this job", so the match has
        # to land in a script. A `rules:` expression comparing the same variable is
        # how a pipeline decides whether to run at all.
        in_shell=True,
        paths=("**/.gitlab-ci.yml", "**/.gitlab-ci.yaml", "**/.gitlab/ci/*.yml"),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.AZURE_INJECTION.001",
        title="Azure Pipelines script interpolates a contributor-controlled value",
        message=(
            "Azure expands `$(...)` macros into the script text before the shell "
            "parses it, and this script expands a value that comes from the branch, "
            "the commit message or a pull request. A commit message containing a "
            "shell metacharacter becomes part of the command, running with the "
            "pipeline's service connections and secret variables."
        ),
        remediation=(
            "Map the value into the step's `env:` and reference it as $VAR (or "
            "$env:VAR in PowerShell), so the shell parses the line before the value "
            "reaches it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"\$\((?:Build\.(?:SourceBranchName|SourceBranch|SourceVersionMessage"
            r"|RequestedFor|RequestedForEmail)"
            r"|System\.PullRequest\.(?:SourceBranch|SourceRepositoryURI))\)"
        ),
        in_shell=True,
        paths=(
            "**/azure-pipelines.yml",
            "**/azure-pipelines.yaml",
            "**/.azure-pipelines/*.yml",
            "**/.azure-pipelines/*.yaml",
        ),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.CIRCLE_INJECTION.001",
        title="CircleCI step interpolates a contributor-controlled pipeline value",
        message=(
            "CircleCI substitutes `<< pipeline.git.* >>` into the step's text before "
            "the shell runs it. A branch or tag name is chosen by whoever opens the "
            "pull request, so it becomes part of the command rather than an argument "
            "to it, with the job's context and environment variables."
        ),
        remediation=(
            "Bind the value to an environment variable in the job's `environment:` "
            'block and reference it as "$VAR" inside the command.'
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(r"<<[ \t]*pipeline\.git\.(?:branch|tag)[ \t]*>>"),
        in_shell=True,
        paths=("**/.circleci/config.yml", "**/.circleci/config.yaml"),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.JENKINS_INJECTION.001",
        title="Jenkins shell step interpolates a contributor-controlled value",
        message=(
            "A Groovy double-quoted string expands `${...}` before the shell step "
            "receives it, and this one expands a value that comes from the branch or "
            "the change request. The expansion happens in Jenkins, so quoting inside "
            "the script cannot help: the value is already part of the command by the "
            "time a shell sees it, and it runs with the credentials the job binds."
        ),
        remediation=(
            "Pass the value through `withEnv` or `environment {}` and reference it as "
            "'$VAR' inside a single-quoted `sh` block, so Groovy leaves it alone and "
            "the shell receives it as data."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"(?:sh|bat|powershell)[ \t]*\(?[ \t]*\"[^\"\n]{0,200}"
            r"\$\{(?:env\.)?(?:BRANCH_NAME|CHANGE_BRANCH|CHANGE_TITLE|CHANGE_AUTHOR"
            r"|CHANGE_AUTHOR_DISPLAY_NAME|GIT_BRANCH|ghprbPullTitle|ghprbSourceBranch)\}"
        ),
        paths=("**/Jenkinsfile", "**/Jenkinsfile.*", "**/*.jenkinsfile"),
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
        pattern=ConfigRule._p(r"^[ \t]*FROM\s+(?!scratch)[^\s@]+(?::[^\s@]+)?\s*(?:AS\s+\w+)?\s*$"),
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
            r"repository[ \t]{0,32}:[ \t]{0,32}[\"']?http://"
            r"|repository[ \t]{0,32}:[ \t]{0,32}[\"']?(?:oci|https)://[^\n]{0,200}\n"
            r"(?:(?![ \t]{0,32}version[ \t]{0,32}:)[^\n]{0,200}\n){0,3}\s{0,8}-\s"
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
            r"[\"']?Action[\"']?[ \t]{0,32}:[ \t]{0,32}[\"']\*[\"']"
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
            r"(?:shell|command|raw)[ \t]{0,32}:[^\n]{0,200}"
            r"(?:curl|wget)[^\n]{0,200}\|[ \t]{0,32}(?:sudo[ \t]{1,8})?(?:sh|bash|python[0-9.]{0,4})"
        ),
        paths=ANSIBLE_PATHS,
    ),
    # -- Version control --------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.SUBMODULE.UNTRUSTED.001",
        title="Submodule fetched over plain HTTP or from a personal account",
        message=(
            "A submodule is fetched over plain HTTP, or tracks a branch rather "
            "than a commit. Submodule content is checked out into the working tree "
            "and built with the project, so whoever controls the source controls "
            "the build -- and a branch reference means what arrives can change "
            "without any commit appearing in this repository."
        ),
        remediation=(
            "Use HTTPS or SSH, and let the submodule stay pinned to the commit "
            "recorded in the parent repository rather than following a branch."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"url[ \t]{0,32}=[ \t]{0,32}(?:http|git)://|^[ \t]{0,32}branch[ \t]{0,32}="
        ),
        paths=("**/.gitmodules",),
    ),
    ConfigRule(
        rule_id="SUSPECT.VCS.HOOKS_PATH.001",
        title="Repository configures its own git hooks directory",
        message=(
            "This repository points git at a hooks directory it ships. Those hooks "
            "run on commit, checkout and merge on the machine of anyone who "
            "configures the repository -- before any code is reviewed, and without "
            "the developer running anything themselves."
        ),
        remediation=(
            "Read every script in the configured directory before enabling it. "
            "Managed hooks are a legitimate practice and are also a way to run code "
            "on a contributor's machine."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(r"hooksPath[ \t]{0,32}="),
        paths=("**/.gitconfig", "**/.git/config", "**/gitconfig"),
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
    # -- Build systems (Domain 4) -----------------------------------------
    ConfigRule(
        rule_id="SUSPECT.BUILD.MAKE_FETCH_EXEC.001",
        title="Makefile recipe fetches and executes remote content",
        message=(
            "A Makefile recipe downloads something and runs it. `make` is the "
            "first command run in most build pipelines, often before any "
            "dependency lock or sandbox is in effect, and what executes is "
            "whatever the remote host serves at that moment."
        ),
        remediation=(
            "Vendor the script, or pin it by digest and verify the digest before running it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # Same mitigation and the same reasoning as SUSPECT.CI.FETCH_EXEC.001:
        # a pinned or checksum-verified fetch is a step down, not silence.
        mitigation=VERIFIED_FETCH,
        pattern=ConfigRule._p(
            r"(?:curl|wget)[^\n|]{0,200}\|[ \t]{0,32}(?:sudo[ \t]{1,8})?(?:ba)?sh"
            r"|(?:curl|wget)[^\n]{0,200}?(?:-o|--output|-O)\s{1,4}[^\s]{1,200}"
            r"[\s\S]{0,240}?chmod\s{1,4}(?:\+x|[0-7]?(?:[1357][0-7][0-7]|[0-7][1357][0-7]|[0-7][0-7][1357]))"
        ),
        paths=MAKE_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="POLICY.BUILD.UNPINNED_DEPENDENCY.001",
        title="Build dependency resolves to whatever is newest, not a fixed version",
        message=(
            "This dependency coordinate uses a floating version: Gradle's `+` "
            "wildcard or Maven's deprecated `LATEST`/`RELEASE`. The build "
            "resolves to whatever the registry currently serves under that "
            "name, so the same coordinate can produce different, unreviewed "
            "code on every build -- and is exactly the substitution a "
            "dependency-confusion attack needs."
        ),
        remediation=(
            "Pin an exact version. If a range is genuinely needed, use a "
            "bounded one your build tool locks against a resolved version file."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(
            # Gradle: `'group:artifact:1.+'` or `'group:artifact:+'`, single or
            # double quoted. The version segment ends in a bare `+`.
            r"""['"][A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+:[0-9A-Za-z.\-]*\+['"]"""
            # Maven: the deprecated meta-versions, still seen in older POMs.
            r"|<version>\s*(?:LATEST|RELEASE)\s*</version>"
        ),
        paths=GRADLE_MAVEN_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001",
        title="CMake fetches a URL with nothing verifying what it downloaded",
        message=(
            "This `ExternalProject_Add` or `FetchContent_Declare` call fetches "
            "a URL with no `URL_HASH` anywhere nearby, so nothing confirms the "
            "bytes it links into the build are the ones the author reviewed. "
            "The host, or anything between it and the build, can substitute "
            "different content and the build would not notice."
        ),
        remediation=(
            "Add `URL_HASH SHA256=<digest>` (or the equivalent for your CMake "
            "version), or switch to `GIT_REPOSITORY`/`GIT_TAG` pinned to a "
            "commit."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            # A bounded "URL <http-url> ... no URL_HASH before the call closes"
            # window: each step of the repeat consumes exactly one character,
            # so this is linear in the window size, not the backtracking shape
            # the pattern-safety sweep (tests/unit/test_pattern_safety.py)
            # exists to catch.
            r"URL\s+https?://[^\s)]+(?:(?!URL_HASH)[\s\S]){0,400}?\)"
        ),
        paths=CMAKE_PATHS,
        capabilities=(Capability.EGRESS,),
    ),
    ConfigRule(
        rule_id="SUSPECT.BUILD.MSBUILD_FETCH_EXEC.001",
        title="MSBuild target fetches and executes remote content",
        message=(
            "An `<Exec>` target downloads something and pipes or hands it "
            "straight to an interpreter. This runs during `dotnet build` or "
            "`msbuild`, often on a developer machine or a CI runner with "
            "publish credentials, and what runs is decided by whoever answers "
            "the download at build time."
        ),
        remediation=(
            "Vendor the script, or pin it by digest and verify the digest before running it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        mitigation=VERIFIED_FETCH,
        pattern=ConfigRule._p(
            r"(?:curl|wget|Invoke-WebRequest|iwr)[^\n\"]{0,200}\|[ \t]{0,32}"
            r"(?:iex|Invoke-Expression|sh|bash|cmd(?:\.exe)?)"
        ),
        paths=MSBUILD_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
)


class ConfigDetector(BaseDetector):
    """Inspects CI, container and infrastructure configuration."""

    id = "config"
    # 0.3.0: a pinned fetch demotes as a verified one does, a build argument needs a
    # value as well as a name, an interpolation has to reach an interpreter,
    # `pull_request_target` needs a head checkout, and test material is ceilinged.
    version = "0.3.0"
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
        uncommented = self._without_comments(content.raw)
        shell: tuple[tuple[int, int], ...] | None = None
        for rule in RULES:
            if not self._applies(rule, content):
                continue
            if rule.in_shell and shell is None:
                shell = self._shell_regions(uncommented)
            match = self._anchor(rule, uncommented, shell if rule.in_shell else None)
            if match is None:
                continue
            findings.append(self._finding(rule, unit, ctx, match, content))
        findings.extend(self._unapproved_actions(unit, ctx, content))
        return findings

    @staticmethod
    def _anchor(
        rule: ConfigRule,
        uncommented: bytes,
        shell: tuple[tuple[int, int], ...] | None = None,
    ) -> re.Match[bytes] | None:
        """Which match to report, when a rule can fire more than once in a file.

        One finding per rule per file, which is right -- a reader does not need the
        same observation eight times. But WHICH occurrence is reported decides what
        the finding says, and for a rule with a `mitigation` it decides the severity.

        So the unmitigated occurrence wins. A Dockerfile that verifies one download
        and pipes another straight into a shell must be reported on the second, and
        reporting the first would have credited the careless instruction for the
        careful one's checksum -- a hole found by the test written to assert this
        very property, because the detector had always taken `search`, meaning the
        first match in the file.
        """

        def eligible(match: re.Match[bytes]) -> bool:
            """Whether this match counts, given where the rule says it has to land.

            Overlap, not containment. These patterns anchor at the start of a line and
            run forward to the thing they are about, so the match begins on the `run:`
            key and the interpolation it found sits inside the script -- a containment
            test on the start offset rejects every one of them.
            """
            if rule.foreign_kind is not None and rule.foreign_kind.search(
                ConfigDetector._document_window(uncommented, match.start())
            ):
                # The enclosing YAML document says the rule is about something else.
                # See `ConfigRule.foreign_kind`.
                return False
            if shell is None:
                return True
            return any(match.start() < end and start < match.end() for start, end in shell)

        if rule.mitigation is None:
            return next((m for m in rule.pattern.finditer(uncommented) if eligible(m)), None)

        first: re.Match[bytes] | None = None
        for match in rule.pattern.finditer(uncommented):
            if not eligible(match):
                continue
            if first is None:
                first = match
            window = ConfigDetector._span_window(uncommented, shell, match.start(), match.end())
            if rule.mitigation.search(window) is None:
                return match
        # Every occurrence is mitigated, so any of them describes the file; the first
        # is the one a reader scrolls to.
        return first

    @staticmethod
    def _without_comments(raw: bytes) -> bytes:
        """The file with comment text blanked and every byte offset preserved.

        A configuration rule is a claim about what a file CONFIGURES. A commented-out
        block configures nothing, and reading one as a setting inverts the finding in
        the worst case: Celery's Helm chart carries

            securityContext: {}
              # capabilities:
              #   drop:
              #   - ALL

        which was reported at HIGH as "container adds a capability that escapes the
        sandbox". Two things wrong at once, and the comment is only the first --
        `drop: ALL` is the most hardened setting a container can have, and it was
        being read as an `add`. The other bug is fixed on that rule; this fixes the
        class.

        The rule already carried a note about a near miss of the same kind: an
        earlier version matched the phrase "nothing to drop into at all" in a comment
        in this project's own Dockerfile, and was anchored to work around it. That is
        a fix per rule. Comments are a property of the file.

        Replaced with spaces rather than removed, so every offset, line number and
        span stays exactly what it was and a finding still points at the right place.

        `#` inside a quoted string is not a comment -- `password: "a#b"` is a
        password -- so quote state is tracked per line. Getting that wrong would blank
        real content, and blanking content in a security scanner is a false negative.
        """
        if b"#" not in raw:
            return raw

        out = bytearray(raw)
        quote: int | None = None
        index = 0
        length = len(out)
        while index < length:
            character = out[index]
            if character == 0x0A:  # newline ends both a comment and a quoted run
                quote = None
                index += 1
                continue
            if character == 0x5C:  # backslash escapes the next byte
                index += 2
                continue
            if quote is None and character in (0x22, 0x27):  # " '
                quote = character
            elif character == quote:
                quote = None
            elif quote is None and character == 0x23:  # #
                # To the end of the line, which is where every `#` comment ends in
                # YAML, TOML, HCL, Dockerfile, .properties, .ini and shell.
                while index < length and out[index] != 0x0A:
                    out[index] = 0x20
                    index += 1
                continue
            index += 1
        return bytes(out)

    DOCUMENT_SEPARATOR = re.compile(rb"(?m)^---[ \t]*\r?$")
    """YAML's document separator, which is how one stream holds many objects."""

    @staticmethod
    def _document_window(uncommented: bytes, offset: int) -> bytes:
        """The YAML document the offset sits in, bounded by `---` on either side.

        A whole file when there is no separator, which is the single-document case and
        most files. No separator in a Dockerfile or a `.tf` either, so those get the file
        and the question is answered the same way.
        """
        starts = [m.end() for m in ConfigDetector.DOCUMENT_SEPARATOR.finditer(uncommented)]
        begin = max((s for s in starts if s <= offset), default=0)
        end = min((s for s in starts if s > offset), default=len(uncommented))
        return uncommented[begin:end]

    _SHELL_KEY = re.compile(
        rb"""(?m)^([ \t]*)-?[ \t]*(?:run|script|cmd|command|entrypoint|args)[ \t]*:[ \t]*(.*)$""",
    )
    """A YAML key whose value is handed to an interpreter.

    `run:` is the one that matters in GitHub Actions, GitLab CI and Azure Pipelines.
    `script:` is GitLab's spelling and also `actions/github-script`'s input, which is
    JavaScript. `cmd`, `command`, `entrypoint` and `args` are the container spellings,
    and a value interpolated into any of them is part of the command rather than an
    argument to it."""

    @staticmethod
    def _window_for(content: FileContent, rule: ConfigRule, start: int, end: int) -> bytes:
        """The mitigation window for a match, using the file's own shell regions."""
        shell = ConfigDetector._shell_regions(content.raw) if rule.in_shell else None
        return ConfigDetector._span_window(content.raw, shell, start, end)

    @staticmethod
    def _span_window(
        raw: bytes, shell: tuple[tuple[int, int], ...] | None, start: int, end: int
    ) -> bytes:
        """The enclosing shell region if there is one, else the logical line."""
        if shell:
            for region_start, region_end in shell:
                if region_start <= start and end <= region_end:
                    return raw[region_start:region_end]
        return ConfigDetector._mitigation_window(raw, start, end)

    @staticmethod
    def _mitigation_window(raw: bytes, start: int, end: int) -> bytes:
        """The bytes a mitigation has to appear in to count for this match.

        One COMMAND, not a byte count. The window used to be 600 bytes either side,
        which in a compact Dockerfile spans several unrelated `RUN` instructions -- so a
        Dockerfile that pins one download and pipes another straight into a shell
        credited the second for the first's pin. The test written for that property
        asserted the right thing about WHICH occurrence is reported and nothing about
        what counts as its mitigation.

        A shell command is a logical line: one physical line plus every line a trailing
        backslash continues onto, in both directions, because the `curl` and the
        `sha256sum -c` that checks it are usually two clauses of one `&&` chain written
        across continuations.

        A workflow `run:` block is handled by the caller, which passes the block's own
        region: the whole block is one script and a pin at its top legitimately covers a
        fetch at its bottom.
        """
        begin = raw.rfind(b"\n", 0, start) + 1
        while begin > 1 and raw[begin - 2 : begin - 1] == b"\\":
            previous = raw.rfind(b"\n", 0, begin - 1) + 1
            if previous >= begin:
                break
            begin = previous
        finish = end
        while True:
            newline = raw.find(b"\n", finish)
            if newline == -1:
                finish = len(raw)
                break
            finish = newline + 1
            if raw[newline - 1 : newline] != b"\\":
                break
        return raw[begin:finish]

    @staticmethod
    def _shell_regions(raw: bytes) -> tuple[tuple[int, int], ...]:
        """Byte ranges of this document that an interpreter will parse.

        A `run:` value is either on the key's own line or in a block scalar under it,
        and a block scalar ends at the first line indented no deeper than the key --
        which is all the YAML this needs to know. Computed per file and consulted by
        any rule that declares `in_shell`.

        Conservative at the edges: an unparsable shape yields no region, so a rule
        that requires one reports nothing rather than reporting everything.
        """
        regions: list[tuple[int, int]] = []
        for match in ConfigDetector._SHELL_KEY.finditer(raw):
            indent = len(match.group(1).expandtabs(8))
            inline = match.group(2).strip()
            start = match.start(2)
            end = match.end(2)
            if inline and not inline.startswith((b"|", b">")):
                # `run: make build` -- the value is the rest of the line.
                regions.append((start, end))
                continue
            # A block scalar, or an empty value followed by one. It runs until a line
            # indented no deeper than the key.
            position = end + 1
            while position < len(raw):
                line_end = raw.find(b"\n", position)
                if line_end == -1:
                    line_end = len(raw)
                line = raw[position:line_end]
                if line.strip():
                    depth = len(line) - len(line.lstrip())
                    if depth <= indent:
                        break
                position = line_end + 1
            if position > end:
                regions.append((start, min(position, len(raw))))
        return tuple(regions)

    # A `uses:` reference, split into owner and the rest.
    _USES = re.compile(
        # The owner must begin with an alphanumeric, which is what an owner
        # name can begin with. Without that, `uses: ./.github/actions/x` parses
        # as an action published by an owner called ".", and a local action --
        # code already in this repository, reviewed with it -- is reported as a
        # third party.
        rb"""uses[ \t]{0,32}:[ \t]{0,32}["']?([A-Za-z0-9][A-Za-z0-9._-]{0,63})/([^\s"'@]{1,120})"""
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
    @functools.lru_cache(maxsize=131072)
    def _pattern_matches(path: str, pattern: str) -> bool:
        """Whether `path` matches one glob, memoised per (file, pattern).

        `_applies` was calling `PathGlob.matches` once per (rule, pattern)
        pair per file -- roughly 30 rules times ~15 patterns apiece, 13.6
        million calls to check 30,000 files, measured with `cProfile` while
        investigating the 200k-file cliff a stress test found
        (`reviews/2026-09-21-adversarial-security-audit-phase2.md`). Most of
        those calls re-derived an answer already computed moments earlier:
        `IAC_PATHS`, `CI_PATHS` and the rest are module-level constants each
        referenced by several rules, and even rules with *different* `paths`
        tuples often share individual glob strings. Caching at the single
        `(path, pattern)` pair is the finest granularity that still catches
        every kind of reuse; `PathGlob.compile` already caches the compiled
        matcher per pattern, so this is the one remaining repeated unit of
        work -- the match itself.
        """
        return PathGlob.matches(path, pattern)

    @staticmethod
    def _paths_match(path: str, patterns: tuple[str, ...]) -> bool:
        return any(ConfigDetector._pattern_matches(path, p) for p in patterns)

    @staticmethod
    def _applies(rule: ConfigRule, content: FileContent) -> bool:
        """Whether a rule should be evaluated against this file.

        Path first, because it is the cheap test and it is right for Terraform,
        Dockerfiles and workflow files, which live at conventional paths by
        definition. Content second, for the kinds that do not: a Kubernetes
        manifest is a Kubernetes manifest wherever somebody put it.
        """
        if ConfigDetector._paths_match(content.path, rule.paths):
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

        # A mitigation found NEAR the match, not anywhere in the file. A Dockerfile
        # with twenty `RUN` instructions may verify one download and pipe another
        # straight into a shell, and crediting the careless one for the careful one's
        # checksum would be worse than not looking.
        #
        # The window is generous in both directions because a verified fetch is
        # written across several clauses joined by `&&` and a line continuation: the
        # `curl` and the `sha256sum -c` that checks it are typically two or three
        # lines apart, with the expected digest assigned above them.
        mitigated = False
        if rule.mitigation is not None:
            mitigated = (
                rule.mitigation.search(
                    ConfigDetector._window_for(content, rule, match.start(), match.end())
                )
                is not None
            )

        severity = rule.severity
        message = rule.message
        if rule.category is not Category.MALICIOUS and is_test_material(content.path):
            # The ceiling every other content detector already applied, and this one
            # did not. `kubernetes/kubernetes` keeps one YAML per API type under
            # `staging/src/k8s.io/api/testdata/HEAD/`, each a fully-populated example
            # of every field in that type -- so every boolean in it is `true`,
            # including `privileged`, `hostPID`, `hostIPC` and `hostNetwork`. They are
            # round-trip serialisation fixtures: nothing applies them to a cluster.
            #
            # 649 of that repository's 680 `SUSPECT.IAC.PRIVILEGED.001` findings were
            # those files, and `SUSPECT.IAC.PRIVILEGED.001` was 1,584 findings across
            # the measurement corpus -- the third largest group of anything.
            #
            # A ceiling, not an exemption: a privileged pod manifest under `test/` is
            # still a privileged pod manifest, and somebody copying it into production
            # is the reason it stays in the report. What it stops doing is failing the
            # build of the project that owns the API type.
            #
            # Documentation paths are deliberately NOT ceilinged here, though every
            # other detector does ceiling them. `**/*.template` is a documentation
            # glob -- a `config.template` holds placeholder credentials -- and a
            # CloudFormation stack is also a `.template`, which is infrastructure
            # somebody deploys. The corpus sample `cfn-iam-wildcard/stack.template`
            # refused the first attempt at this within one run. Nothing is lost:
            # these rules select on manifest paths and markers, so prose was never
            # reaching them.
            severity = min(severity, FIXTURE_CEILING)
            message = (
                f"{rule.message} It sits under a path that holds test material, where "
                f"a manifest is usually a fixture for the code that parses it rather "
                f"than something applied to a cluster, so it is reported below its "
                f"usual severity."
            )
        elif rule.category is not Category.MALICIOUS and is_generated_artefact(content.path):
            severity = min(severity, FIXTURE_CEILING)
            message = (
                f"{rule.message} It sits in generated output rather than in source "
                f"somebody wrote, so it is reported below its usual severity."
            )
        elif rule.category is not Category.MALICIOUS and content.is_rule_material:
            # `semgrep/semgrep-rules` holds `terraform/aws/security/aws-iam-admin-policy.tf`
            # with an IAM wildcard in it, and `yaml/kubernetes/security/privileged-container.yaml`
            # whose `privileged: true` is a PATTERN rather than a deployment. Neither
            # is infrastructure anybody applies. See `core.samples`.
            severity = min(severity, RULE_MATERIAL_CEILING)
            message = (
                f"{rule.message} The file is another analyser's rule material -- a rule "
                f"set, or a test case annotated for one -- so the shape was written in "
                f"order to be matched rather than deployed. Reported for the record only."
            )
        elif mitigated:
            severity = rule.severity.demote()
            message = (
                f"{rule.message} The same instruction verifies what it downloaded, "
                f"which is the control this rule asks for, so it is reported one step "
                f"lower - a verified fetch is still a fetch, and a build reaching the "
                f"network is worth a line in the report."
            )

        return Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=severity,
            confidence=rule.confidence,
            message=message,
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
