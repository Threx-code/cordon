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
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.decide.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.infra.ci_exfil import (
    ONE_COMMAND_BREAK,
)
from cordon_scanner.detect.secrets.secrets import RULE_MATERIAL_CEILING
from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.models import (
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
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.foundation.text.redact import Redactor
from cordon_scanner.intel.registries.installers import OfficialInstallers

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.detect.infra.ci_rules import (
    CI_RULES,
    FORK_GUARD,
    GITHUB_WORKFLOW_PATHS,
    REPARSED,
    SECRET_BESIDE_EGRESS,
    SERIALISED_SECRETS,
    TRUSTED_ACTOR_GATE,
    UNTRUSTED_DESTINATION,
    UNTRUSTED_TRIGGER,
)
from cordon_scanner.detect.infra.config_paths import (
    CI_PATHS,
    DOCKER_PATHS,
    IAC_PATHS,
    K8S_MARKER,
    VERIFIED_FETCH,
)
from cordon_scanner.detect.infra.config_rule import ConfigRule
from cordon_scanner.detect.infra.container_rules import (
    CONTAINER_RULES,
    HELM_PATHS,
    KUBERNETES_RULES,
)
from cordon_scanner.detect.infra.infrastructure_rules import (
    ANSIBLE_PATHS,
    ANSIBLE_RULES,
    CFN_MARKER,
    CFN_PATHS,
    CLOUDFORMATION_RULES,
    INFRASTRUCTURE_RULES,
)
from cordon_scanner.detect.infra.repository_rules import (
    BUILD_RULES,
    CMAKE_PATHS,
    GRADLE_MAVEN_PATHS,
    MAKE_PATHS,
    MSBUILD_PATHS,
    VERSION_CONTROL_RULES,
)

UNPINNED_RULE = "POLICY.BUILD.UNPINNED_DEPENDENCY.001"
"""What `^` becomes: start of line, then an optional byte-order mark.

Built from the character itself rather than an escape, because `re.sub`
reads its replacement as a template and `\\u` is not a template escape.
"""


ANSIBLE_MARKER = b"hosts:"
"""What identifies an Ansible play.

Weaker than the others, and paired with a task keyword in every rule that uses
it, because `hosts:` alone appears in plenty of unrelated configuration."""


CONTENT_MARKER_BYTES = 4096
"""How far into a file to look for a content marker.

A manifest declares `apiVersion` at the top. Scanning further would cost more
and find only files that mention the word in passing."""


RULES: tuple[ConfigRule, ...] = (
    *CI_RULES,
    *CONTAINER_RULES,
    *INFRASTRUCTURE_RULES,
    *KUBERNETES_RULES,
    *CLOUDFORMATION_RULES,
    *ANSIBLE_RULES,
    *VERSION_CONTROL_RULES,
    *BUILD_RULES,
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
            if rule.rule_id == UNPINNED_RULE and self._all_floating_locked(
                rule, uncommented, unit.path, ctx
            ):
                continue
            findings.append(self._finding(rule, unit, ctx, match, content))
        findings.extend(self._unapproved_actions(unit, ctx, content))
        return findings

    @staticmethod
    def _all_floating_locked(
        rule: ConfigRule, uncommented: bytes, path: str, ctx: ScanContext
    ) -> bool:
        """Whether every floating coordinate in a Gradle script is pinned by dependency locking.

        With a `gradle.lockfile` committed, Gradle resolves `2.+` to the locked version and fails
        the build rather than take another: the version does not float. Known from the inventory
        -- a declaration in this script joined to a lockfile entry -- and only then."""
        locked = {
            d.name.lower()
            for d in ctx.dependencies
            if d.manifest_path == path
            and d.declared_in
            and d.declared_in.endswith(".lockfile")
            and d.version
        }
        if not locked:
            return False
        floating = [
            m.group(0).decode("utf-8", "replace").strip("'\"").rsplit(":", 1)[0].lower()
            for m in rule.pattern.finditer(uncommented)
        ]
        return bool(floating) and all(name in locked for name in floating)

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

        if rule.require_aggravation and rule.aggravation is not None:
            aggravation, confirm = rule.aggravation, rule.confirm

            def claimed(m: re.Match[bytes]) -> bool:
                window = ConfigDetector._span_window(uncommented, shell, m.start(), m.end())
                if confirm is not None:
                    return confirm(aggravation, window, uncommented)
                return aggravation.search(window) is not None

            if not rule.one_command:
                return next(
                    (
                        m
                        for m in rule.pattern.finditer(uncommented)
                        if ConfigDetector._eligible(rule, uncommented, shell, m) and claimed(m)
                    ),
                    None,
                )
            # Searched one logical command at a time: a match that spans two commands is not this
            # rule's claim, and letting the regex consume it would hide the same-line pair after it.
            start = 0
            for brk in [*ONE_COMMAND_BREAK.finditer(uncommented), None]:
                end = brk.start() if brk is not None else len(uncommented)
                for m in rule.pattern.finditer(uncommented, start, end):
                    if ConfigDetector._eligible(rule, uncommented, shell, m) and claimed(m):
                        return m
                start = brk.end() if brk is not None else end
            return None
        if rule.mitigation is None:
            return next(
                (
                    m
                    for m in rule.pattern.finditer(uncommented)
                    if ConfigDetector._eligible(rule, uncommented, shell, m)
                ),
                None,
            )

        first: re.Match[bytes] | None = None
        for match in rule.pattern.finditer(uncommented):
            if not ConfigDetector._eligible(rule, uncommented, shell, match):
                continue
            if first is None:
                first = match
            window = ConfigDetector._span_window(uncommented, shell, match.start(), match.end())
            if rule.mitigation is VERIFIED_FETCH and OfficialInstallers.is_official_installer(
                match.group(0).decode("utf-8", "replace")
            ):
                # `curl -LsSf https://astral.sh/uv/install.sh | sh`: the vendor's own host
                # serving the vendor's own installer, which is what its documentation says to
                # run. Treated like a pinned fetch -- one step down, still reported.
                continue
            if rule.mitigation.search(window) is None:
                return match
        # Every occurrence is mitigated, so any of them describes the file; the first
        # is the one a reader scrolls to.
        return first

    @staticmethod
    def _eligible(
        rule: ConfigRule,
        uncommented: bytes,
        shell: tuple[tuple[int, int], ...] | None,
        match: re.Match[bytes],
    ) -> bool:
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
        if rule.outbound_exempt and ConfigDetector._is_outbound(uncommented, match):
            # An egress rule. See `ConfigRule.outbound_exempt`.
            return False
        if rule.enclosing_key and not (
            set(ConfigDetector._enclosing_keys(uncommented, match)) & set(rule.enclosing_key)
        ):
            # The value is real and belongs to a different key, which means
            # something else. See `ConfigRule.enclosing_key`.
            return False
        if shell is None:
            return True
        return any(match.start() < end and start < match.end() for start, end in shell)

    #: A block that declares outbound traffic: Terraform's `type = "egress"` on an
    #: `aws_security_group_rule` (or a module's rule map), GCP's and Azure's `direction`.
    OUTBOUND_FIELD = re.compile(
        rb"""(?i)\btype["']?[ \t]*[=:][ \t]*["']egress["']"""
        rb"""|\bdirection["']?[ \t]*[=:][ \t]*["']?(?:egress|outbound)\b"""
    )
    #: The line opening a block named for egress: `egress {`, `egress_all = {`.
    OUTBOUND_OPENER = re.compile(rb"""(?i)[ \t]*["']?egress\w*["']?[ \t]*[=:]?[ \t]*\{""")
    #: CloudFormation's two lists and two resource types; whichever is nearest above a match
    #: is the one it belongs to.
    CLOUDFORMATION_DIRECTION = re.compile(rb"SecurityGroup(In|E)gress")

    @staticmethod
    def _is_outbound(raw: bytes, match: re.Match[bytes]) -> bool:
        """Whether the block holding this match is a rule for outbound traffic.

        `cidr_blocks = ["0.0.0.0/0"]` with `from_port = 0` is every port open to the internet
        in an ingress rule and every destination allowed in an egress one -- and an egress rule
        open to everywhere is the default every AWS security group starts with. Found scanning
        terraform-aws-eks, whose recommended node rules end in `egress_all`, reported HIGH as
        "ingress permitted from the entire internet".

        The innermost braces around the match (the pattern holds none, so it sits in one block)
        and the line that opens them; for CloudFormation, the nearest of its Ingress and Egress
        keys above the match, which also covers YAML, where there are no braces.
        """
        opening = raw.rfind(b"{", 0, match.start())
        if opening >= 0:
            closing = raw.find(b"}", match.end())
            line_start = raw.rfind(b"\n", 0, opening) + 1
            if ConfigDetector.OUTBOUND_OPENER.match(raw, line_start, opening + 1):
                return True
            block = raw[opening : closing if closing >= 0 else len(raw)]
            if ConfigDetector.OUTBOUND_FIELD.search(block):
                return True
        nearest = None
        for found in ConfigDetector.CLOUDFORMATION_DIRECTION.finditer(raw, 0, match.start()):
            nearest = found
        return nearest is not None and nearest.group(1) == b"E"

    #: How far above a match to look for the key whose block holds it. A step's
    #: `with:` or `env:` is a handful of lines up; two hundred is generous for
    #: that and stops a pathological file walking to its own start.
    ENCLOSING_LOOKBACK = 200

    @staticmethod
    def _enclosing_keys(raw: bytes, match: re.Match[bytes]) -> tuple[bytes, ...]:
        """The key on the match's own line, and the key whose block contains it.

        Both, because either can be the one a rule means. `- run: curl ...` holds
        the value on the key's own line; `ALLMYSECRETS: ${{ ... }}` under `env:`
        holds it in a mapping the key opened, and a rule about `run` and a rule
        about `env` each has to see the one it is about.

        Indentation is what says which block a line belongs to, so this walks
        back to the nearest line indented less than the match's and takes its
        key. A sequence dash is skipped on both, because `- name: x` is indented
        two further than the `steps:` it belongs to and reads as a deeper block
        otherwise.
        """
        line_start = raw.rfind(b"\n", 0, match.start()) + 1
        line_end = raw.find(b"\n", match.start())
        line = raw[line_start : line_end if line_end != -1 else len(raw)]

        found: list[bytes] = []
        own = ConfigDetector._KEY_ON_LINE.match(line)
        if own is not None and line_start + own.end() <= match.start():
            found.append(own.group("key"))

        indent = ConfigDetector._indent(line)
        cursor = line_start
        for _ in range(ConfigDetector.ENCLOSING_LOOKBACK):
            if cursor <= 0:
                break
            cursor = raw.rfind(b"\n", 0, cursor - 1) + 1
            above_end = raw.find(b"\n", cursor)
            above = raw[cursor : above_end if above_end != -1 else len(raw)]
            if not above.strip():
                continue
            above_indent = ConfigDetector._indent(above)
            if above_indent >= indent:
                continue
            key = ConfigDetector._KEY_ON_LINE.match(above)
            if key is not None:
                found.append(key.group("key"))
                break
            indent = above_indent
        return tuple(found)

    #: A mapping key at the head of a line, with the sequence dash a step is
    #: written with treated as indentation rather than as part of the key.
    _KEY_ON_LINE = re.compile(rb"[ \t]{0,64}(?:-[ \t]{1,4})?(?P<key>[\w.\-]{1,64})[ \t]{0,8}:")

    @staticmethod
    def _indent(line: bytes) -> int:
        """How deep a line sits, counting the sequence dash as part of the depth."""
        stripped = line.lstrip(b" \t")
        depth = len(line) - len(stripped)
        if stripped.startswith(b"-"):
            rest = stripped[1:].lstrip(b" \t")
            depth += len(stripped) - len(rest)
        return depth

    _OUTSIDE_QUOTES: ClassVar[re.Pattern[bytes]] = re.compile(rb"[\n\\\"'#]")
    """Outside a quoted run, the bytes `_without_comments` acts on."""
    _INSIDE: ClassVar[dict[int, re.Pattern[bytes]]] = {
        0x22: re.compile(rb'[\n\\"]'),
        0x27: re.compile(rb"[\n\\']"),
    }
    """Inside a run opened by each quote: what ends it, and the backslash."""

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
        Read by jumping between the five bytes that change state -- newline, backslash, the two
        quotes, `#` -- rather than visiting every byte in Python: 15.9 s to 2.0 s over ten thousand
        files of ordinary packages, the same output for every file and for 200,000 random strings
        over those bytes (`tests/unit/detect/infra/test_config_comment_blanking.py`).
        """
        if b"#" not in raw:
            return raw

        out: bytearray | None = None
        quote: int | None = None
        index = 0
        length = len(raw)
        while index < length:
            found = (
                ConfigDetector._OUTSIDE_QUOTES if quote is None else ConfigDetector._INSIDE[quote]
            ).search(raw, index)
            if found is None:
                break
            index = found.start()
            character = raw[index]
            if character == 0x0A:  # newline ends both a comment and a quoted run
                quote = None
                index += 1
            elif character == 0x5C:  # backslash escapes the next byte
                index += 2
            elif quote is None and character == 0x23:  # `#`: to the end of the line
                # Which is where every `#` comment ends in YAML, TOML, HCL, Dockerfile,
                # .properties, .ini and shell.
                end = raw.find(b"\n", index)
                end = length if end < 0 else end
                if out is None:
                    out = bytearray(raw)
                out[index:end] = b" " * (end - index)
                index = end
            elif quote is None:  # a quote opens
                quote = character
                index += 1
            else:  # the open quote closes
                quote = None
                index += 1
        return raw if out is None else bytes(out)

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
        rb"""(?m)^([ \t]*)-?[ \t]*(?:run|script|cmd|commands|command|entrypoint|args)[ \t]*:[ \t]*(.*)$""",
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
                references=rule.references,
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
        name = ContainerPaths.basename(content.path).lower()
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
            ) or (
                rule.mitigation is VERIFIED_FETCH
                and OfficialInstallers.is_official_installer(
                    match.group(0).decode("utf-8", "replace")
                )
            )

        severity = rule.severity
        message = rule.message
        message, severity = ConfigDetector._ceiling(
            content, match, message, mitigated, rule, severity
        )

        return self._scored(content, ctx, line, match, message, rule, severity, unit)

    @staticmethod
    def _ceiling(
        content: FileContent,
        match: re.Match[bytes],
        message: str,
        mitigated: bool,
        rule: ConfigRule,
        severity: Severity,
    ) -> tuple[str, Severity]:
        """The ceiling a configuration finding's place puts on it -- test material, generated output, another analyser's rule material -- and what the message says about it."""
        if rule.category is not Category.MALICIOUS and SourcePaths.is_test_material(content.path):
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
        elif rule.category is not Category.MALICIOUS and SourcePaths.is_generated_artefact(
            content.path
        ):
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
        elif rule.aggravation is not None and (
            rule.aggravation.search(
                content.raw
                if rule.aggravation_in_file
                else ConfigDetector._window_for(content, rule, match.start(), match.end())
            )
            is None
        ):
            severity = min(severity, Severity.LOW)
            message = (
                f"{rule.message} Nothing in the workflow lets an outside contributor's run write "
                f"to it -- no `pull_request_target`, `issue_comment` or `workflow_run` trigger -- "
                f"so it is recorded rather than raised."
                if rule.aggravation_in_file
                else f"{rule.message} Nothing near it sends to a destination a pipeline has no "
                f"business with -- a paste site, a tunnel, a bare IP address -- so it is "
                f"recorded rather than raised."
            )
        elif mitigated:
            severity = rule.severity.demote()
            message = (
                f"{rule.message} The same instruction verifies what it downloaded, "
                f"which is the control this rule asks for, so it is reported one step "
                f"lower - a verified fetch is still a fetch, and a build reaching the "
                f"network is worth a line in the report."
            )
        return message, severity

    def _scored(
        self,
        content: FileContent,
        ctx: ScanContext,
        line: int,
        match: re.Match[bytes],
        message: str,
        rule: ConfigRule,
        severity: Severity,
        unit: FileUnit,
    ) -> Finding:
        """The configuration finding, scored, with its evidence and the reasons for its grade."""
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
            references=rule.references,
            capabilities=rule.capabilities,
        )


__all__ = [
    "ANSIBLE_MARKER",
    "ANSIBLE_PATHS",
    "CFN_MARKER",
    "CFN_PATHS",
    "CI_PATHS",
    "CMAKE_PATHS",
    "CONTENT_MARKER_BYTES",
    "DOCKER_PATHS",
    "FORK_GUARD",
    "GITHUB_WORKFLOW_PATHS",
    "GRADLE_MAVEN_PATHS",
    "HELM_PATHS",
    "IAC_PATHS",
    "K8S_MARKER",
    "MAKE_PATHS",
    "MSBUILD_PATHS",
    "REPARSED",
    "RULES",
    "SECRET_BESIDE_EGRESS",
    "SERIALISED_SECRETS",
    "TRUSTED_ACTOR_GATE",
    "UNPINNED_RULE",
    "UNTRUSTED_DESTINATION",
    "UNTRUSTED_TRIGGER",
    "VERIFIED_FETCH",
    "ConfigDetector",
]
