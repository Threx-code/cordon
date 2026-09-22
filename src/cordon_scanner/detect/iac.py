"""Infrastructure-as-code policy, evaluated per resource rather than per file.

`detect/config_files.py` matches patterns against a whole file, which answers
"does this file contain something alarming" and cannot answer the question most
infrastructure policy is about: *this* resource is missing *that* setting. A
regex cannot express absence over a region it has no notion of, so the rules
there are all "something insecure is written down", and the much larger half --
the setting nobody wrote -- was out of reach.

This detector reads the file into blocks first. A Terraform `resource` block, a
Kubernetes document, a CloudFormation resource and a Compose service are each a
span of text with a type and a name, and once the span exists both questions are
answerable inside it:

    forbid   an attribute is present and its value matches   (encrypted = false)
    require  an attribute is absent from the block           (no encryption at all)

Policies are data (`detect/iac_policies.py`), not code. Each one carries the two
samples that decide whether it works -- one that must fire and one that must not
-- and `tests/unit/test_iac_policies.py` runs every pair on every push, the same
discipline `cordon-scanner rules test` applies to the YAML packs. A policy that
stops matching is a policy that fails the build rather than one that quietly
reports nothing.

What this deliberately does not do is parse HCL or YAML properly. A block is
found by its header and its braces, or by its document separator and its
indentation; attributes are matched inside that span. The cost is that a
pathologically formatted file can hide a resource from a policy, and the benefit
is that the core keeps its zero third-party dependencies and that a malformed
file degrades to fewer findings rather than to an exception.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.models import (
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
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import ScanContext, Unit


TERRAFORM_SUFFIXES = (".tf", ".tf.json", ".hcl")
YAML_SUFFIXES = (".yaml", ".yml")

#: A Kubernetes document declares both of these, wherever it lives.
K8S_MARKERS = (b"apiVersion:", b"kind:")

#: A CloudFormation template declares its resources under this key, and either
#: names the format version or uses the `AWS::` type prefix inside.
CFN_MARKERS = (b"Resources:", b"AWS::")

#: A Compose file names its services and, unlike every other YAML here, has no
#: `kind:` to identify it.
COMPOSE_MARKERS = (b"services:",)


@dataclass(frozen=True, slots=True)
class Block:
    """One resource: its type, its name, and the text between its boundaries."""

    kind: str
    """The policy-facing type, normalised per format: `aws_s3_bucket` for
    Terraform, `k8s:Deployment` for Kubernetes, `cfn:AWS::S3::Bucket` for
    CloudFormation, `compose:service` for a Compose service."""

    name: str
    body: str
    start: int
    """Offset of the block header in the file, for the finding's location."""


@dataclass(frozen=True, slots=True)
class IacPolicy:
    """One control, and the two samples that prove it works.

    `forbid` and `require` are the two halves of infrastructure policy, and a
    policy uses one of them:

    `forbid`
        The block says something insecure. `(attribute, value)` is a pair of
        patterns: the attribute name as written, and what its value must look
        like for the policy to fire. `encrypted\\s*=\\s*false`.

    `require`
        The block does not say something it should. The pattern is what a
        compliant block would contain, and the finding is reported when it is
        absent -- which is the shape a file-level regex cannot express.
    """

    id: str
    title: str
    message: str
    remediation: str
    severity: Severity
    confidence: Confidence
    resources: tuple[str, ...]
    """Block kinds this applies to. A trailing `*` matches a prefix, so
    `aws_rds_*` covers every RDS resource the provider names."""

    bad: str
    """A block body this policy must report. Held with the policy rather than in
    a test file so that adding a policy and proving it works are one edit."""

    good: str
    """A block body this policy must not report -- normally the remediation the
    message recommends, which is the sample that catches an over-broad pattern."""

    category: Category = Category.POLICY
    forbid: tuple[str, ...] = ()
    require: tuple[str, ...] = ()
    unless: tuple[str, ...] = ()
    """Evidence inside the same block that the control is met another way. A
    policy that ignores the alternative spelling reports the compliant case."""

    when: tuple[str, ...] = ()
    """What the block must contain for the policy to apply at all.

    Distinct from `unless`, and the distinction is the same one `foreign_kind`
    draws in the config rules: `unless` says the weakness is controlled, this
    says the policy is about something else entirely. A health check belongs to
    an image that serves a port; requiring one of a command-line image reports a
    control that would do nothing.
    """

    references: tuple[str, ...] = ()

    _when: tuple[re.Pattern[str], ...] = field(default=(), init=False, repr=False, compare=False)
    _forbid: tuple[re.Pattern[str], ...] = field(default=(), init=False, repr=False, compare=False)
    _require: tuple[re.Pattern[str], ...] = field(default=(), init=False, repr=False, compare=False)
    _unless: tuple[re.Pattern[str], ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.forbid and not self.require:
            raise ValueError(f"{self.id}: a policy must forbid something or require something")
        if self.forbid and self.require:
            raise ValueError(
                f"{self.id}: a policy is about a value that is written or one that is "
                f"missing, never both -- two claims in one id cannot be acted on"
            )
        compiled = re.IGNORECASE | re.MULTILINE
        object.__setattr__(self, "_forbid", tuple(re.compile(p, compiled) for p in self.forbid))
        object.__setattr__(self, "_require", tuple(re.compile(p, compiled) for p in self.require))
        object.__setattr__(self, "_unless", tuple(re.compile(p, compiled) for p in self.unless))
        object.__setattr__(self, "_when", tuple(re.compile(p, compiled) for p in self.when))

    def applies_to(self, kind: str) -> bool:
        for wanted in self.resources:
            if wanted.endswith("*"):
                if kind.startswith(wanted[:-1]):
                    return True
            elif kind == wanted:
                return True
        return False

    def evaluate(self, block: Block) -> re.Match[str] | bool | None:
        """The match that proves the policy fired, or None.

        A `forbid` policy returns the match so the finding can point at the line
        that says the insecure thing. A `require` policy has nothing to point
        at -- the finding is about what is not there -- so it returns True and
        the finding lands on the block header.
        """
        if not all(pattern.search(block.body) for pattern in self._when):
            return None
        if any(pattern.search(block.body) for pattern in self._unless):
            return None
        for pattern in self._forbid:
            found = pattern.search(block.body)
            if found is not None:
                return found
        if self._require and not any(p.search(block.body) for p in self._require):
            return True
        return None


def terraform_blocks(text: str) -> Iterator[Block]:
    """Every `resource`/`data`/`module` block, by header and brace balance.

    Strings and comments are stepped over while counting, because a brace inside
    either is not a brace: a policy document written as a heredoc closes the
    block early otherwise, and every attribute after it is read as belonging to
    the next resource.
    """
    for header in _TF_HEADER.finditer(text):
        body_start = text.find("{", header.end() - 1)
        if body_start == -1:
            continue
        end = _balanced_end(text, body_start)
        if end is None:
            continue
        block = header.group("block")
        yield Block(
            kind=header.group("type") if block is None else f"{block}:{header.group('label')}",
            name=(header.group("name") if block is None else header.group("label")) or "",
            body=text[body_start + 1 : end],
            start=header.start(),
        )


_TF_HEADER = re.compile(
    r"""^[ \t]*(?:
        resource[ \t]+"(?P<type>[A-Za-z0-9_\-]+)"[ \t]+"(?P<name>[^"]*)"
        |(?P<block>provider|backend|module)[ \t]+"(?P<label>[^"]*)"
    )[ \t]*\{""",
    re.MULTILINE | re.VERBOSE,
)
"""The block headers a policy can be written against.

`resource` is the obvious one. `provider` and `backend` are here because the
two things most worth reporting in a Terraform file are not resources at all: a
static credential lives in a provider block, and the state backend -- which
holds every sensitive value the plan touched -- is configured in a `backend`
block inside `terraform`. A policy scoped to resources could never see either.
"""

_HEREDOC = re.compile(r"<<-?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)")


def _balanced_end(text: str, open_brace: int) -> int | None:
    """The offset of the brace closing the one at `open_brace`, or None.

    Bounded by the end of the text, and it steps over quoted strings, `#` and
    `//` comments, `/* */` comments and heredocs -- the four places a brace in
    Terraform means nothing structurally.
    """
    depth = 0
    index = open_brace
    length = len(text)
    while index < length:
        char = text[index]
        if char == '"':
            index = _skip_quoted(text, index)
            continue
        if char == "#" or text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if char == "<":
            heredoc = _HEREDOC.match(text, index)
            if heredoc is not None:
                terminator = f"\n{heredoc.group('tag')}"
                close = text.find(terminator, heredoc.end())
                index = length if close == -1 else close + len(terminator)
                continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _skip_quoted(text: str, index: int) -> int:
    """Past a double-quoted string that opens at `index`."""
    index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index + 1
        index += 1
    return index


def yaml_documents(text: str) -> Iterator[tuple[str, int]]:
    """Each `---`-separated document, with its offset in the file."""
    offset = 0
    for part in re.split(r"(?m)^---[ \t]*\r?$", text):
        yield part, offset
        offset += len(part) + 4


def kubernetes_blocks(text: str) -> Iterator[Block]:
    """One block per document, typed by its `kind:`.

    The whole document is the body. A pod template is nested inside a Deployment
    and its settings belong to the Deployment as far as policy is concerned, so
    splitting further would only make every policy name two kinds.
    """
    for document, offset in yaml_documents(text):
        kind = _K8S_KIND.search(document)
        if kind is None:
            continue
        name = _K8S_NAME.search(document)
        yield Block(
            kind=f"k8s:{kind.group(1)}",
            name=name.group(1) if name else "",
            body=document,
            start=offset,
        )


# `\r?$` rather than `$` throughout this module. Under `re.MULTILINE`, `$`
# matches before the `\n` and does not step over the `\r` in front of it, so
# every anchored pattern here silently stops matching on a file written on
# Windows -- and a manifest that is not recognised as Kubernetes is a manifest no
# policy is evaluated against.
_K8S_KIND = re.compile(r"(?m)^kind:[ \t]*([A-Za-z][A-Za-z0-9]*)[ \t]*\r?$")
_K8S_NAME = re.compile(r"(?m)^[ \t]{2}name:[ \t]*([A-Za-z0-9._\-]+)")


def cloudformation_blocks(text: str) -> Iterator[Block]:
    """Each resource under `Resources:`, delimited by indentation.

    A CloudFormation resource is a mapping whose `Type:` names it, and its body
    runs until the next key at the same indent. That is enough structure for the
    same two questions, without a YAML parser.
    """
    resources = re.search(r"(?m)^Resources:[ \t]*\r?$", text)
    if resources is None:
        return
    region = text[resources.end() :]
    base = resources.end()
    for match in _CFN_RESOURCE.finditer(region):
        indent = len(match.group("indent"))
        end = len(region)
        for following in _CFN_RESOURCE.finditer(region, match.end()):
            if len(following.group("indent")) <= indent:
                end = following.start()
                break
        body = region[match.start() : end]
        type_name = _CFN_TYPE.search(body)
        if type_name is None:
            continue
        yield Block(
            kind=f"cfn:{type_name.group(1)}",
            name=match.group("key"),
            body=body,
            start=base + match.start(),
        )


_CFN_RESOURCE = re.compile(r"(?m)^(?P<indent>[ \t]{2,8})(?P<key>[A-Za-z0-9]+):[ \t]*\r?$")
_CFN_TYPE = re.compile(r"(?m)^[ \t]*Type:[ \t]*['\"]?(AWS::[A-Za-z0-9:]+)")


def compose_services(text: str) -> Iterator[Block]:
    """Each service in a Compose file, delimited by indentation."""
    services = re.search(r"(?m)^services:[ \t]*\r?$", text)
    if services is None:
        return
    region = text[services.end() :]
    base = services.end()
    for match in _COMPOSE_SERVICE.finditer(region):
        indent = len(match.group("indent"))
        end = len(region)
        for following in _COMPOSE_SERVICE.finditer(region, match.end()):
            if len(following.group("indent")) <= indent:
                end = following.start()
                break
        yield Block(
            kind="compose:service",
            name=match.group("key"),
            body=region[match.start() : end],
            start=base + match.start(),
        )


_COMPOSE_SERVICE = re.compile(r"(?m)^(?P<indent>[ \t]{2,4})(?P<key>[A-Za-z0-9._\-]+):[ \t]*\r?$")


def blocks_for(path: str, text: str, raw: bytes) -> tuple[Block, ...]:
    """Every block this file holds, by format.

    Identified by content where content decides -- a Kubernetes manifest is one
    wherever somebody put it -- and by suffix only for Terraform, whose files
    have no marker other than being HCL.
    """
    text = text.lstrip("\ufeff")
    lowered = path.lower()
    if lowered.endswith(TERRAFORM_SUFFIXES):
        return tuple(terraform_blocks(text))
    # A Dockerfile has no resource boundaries: the file is the image, and every
    # policy about it is about what the whole build produces.
    name = lowered.rpartition("/")[2]
    if name.startswith(("dockerfile", "containerfile")) or name.endswith(
        (".dockerfile", ".containerfile")
    ):
        return (Block(kind="dockerfile", name=name, body=text, start=0),)
    if not lowered.endswith(YAML_SUFFIXES):
        return ()
    if all(marker in raw for marker in K8S_MARKERS):
        return tuple(kubernetes_blocks(text))
    if all(marker in raw for marker in CFN_MARKERS):
        return tuple(cloudformation_blocks(text))
    if any(marker in raw for marker in COMPOSE_MARKERS):
        return tuple(compose_services(text))
    return ()


class IacDetector(BaseDetector):
    """Evaluates the policy table against the resources a file declares."""

    id = "iac"
    version = "0.1.0"
    categories = frozenset({Category.POLICY, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True, dependencies=False)

    def __init__(self, policies: tuple[IacPolicy, ...] | None = None) -> None:
        from cordon_scanner.detect.iac_policies import CURATED, generated_rows

        self.policies = CURATED if policies is None else policies
        by_kind: dict[str, list[IacPolicy]] = {}
        self._prefix: list[IacPolicy] = []
        for policy in self.policies:
            for resource in policy.resources:
                if resource.endswith("*"):
                    self._prefix.append(policy)
                else:
                    by_kind.setdefault(resource, []).append(policy)
        self._by_kind = by_kind

        # The generated half stays as rows until a file names the resource. A
        # thousand policies is a thousand patterns to compile, and a scan asks
        # about the handful of resource kinds its files actually declare -- so a
        # repository with one `aws_s3_bucket` builds the policies for buckets
        # and nothing else, and a repository with no infrastructure in it builds
        # none of them.
        self._rows: dict[str, tuple[dict[str, Any], ...]] = (
            {} if policies is not None else generated_rows()
        )
        self._built: dict[str, tuple[IacPolicy, ...]] = {}

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        """Every policy, curated and generated.

        Asked by `rules list`, `rules show` and the coverage matrix, never on
        the scan path: it builds the whole set, which is the thing `_generated`
        exists to avoid doing for a scan.
        """
        from cordon_scanner.detect.iac_policies import all_policies

        return tuple(
            DeclaredRule(
                id=policy.id,
                title=policy.title,
                severity=policy.severity,
                confidence=policy.confidence,
                category=policy.category,
                detector=IacDetector.id,
                message=policy.message,
                remediation=policy.remediation,
            )
            for policy in all_policies()
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def _for(self, kind: str) -> Iterable[IacPolicy]:
        yield from self._by_kind.get(kind, ())
        for policy in self._prefix:
            if policy.applies_to(kind):
                yield policy
        yield from self._generated(kind)

    def _generated(self, kind: str) -> tuple[IacPolicy, ...]:
        """The generated policies for one resource kind, built once."""
        built = self._built.get(kind)
        if built is None:
            from cordon_scanner.detect.iac_policies import policy_from_row

            rows = self._rows.get(kind, ())
            built = tuple(policy_from_row(row) for row in rows)
            self._built[kind] = built
        return built

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()
        content = unit.content
        blocks = blocks_for(content.path, content.text, content.raw)
        if not blocks:
            return ()

        findings: list[Finding] = []
        for block in blocks:
            for policy in self._for(block.kind):
                outcome = policy.evaluate(block)
                if outcome is None:
                    continue
                findings.append(self._finding(policy, block, outcome, unit, content, ctx))
        return findings

    def _finding(
        self,
        policy: IacPolicy,
        block: Block,
        outcome: re.Match[str] | bool,
        unit: FileUnit,
        content: FileContent,
        ctx: ScanContext,
    ) -> Finding:
        if isinstance(outcome, re.Match):
            # `body` is a slice of the file, so the match offset is relative to
            # the block and the line number is not.
            offset = block.start + block.body.find(outcome.group(0))
            snippet = outcome.group(0)
        else:
            offset = block.start
            snippet = content.line_text(content.line_of(block.start)).strip()
        line = content.line_of(max(offset, 0))

        subject = f"{block.kind} {block.name}".strip()
        message = f"{subject}: {policy.message}"
        return Finding(
            rule_id=policy.id,
            category=policy.category,
            severity=policy.severity,
            confidence=policy.confidence,
            message=message,
            location=Location(
                path=content.path,
                line=line,
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(f"{policy.id}:{subject}".encode()),
                redaction=RedactionMode.MASKED,
                # Masked for the reason the CI rules are: infrastructure is one
                # of the likelier places for a credential to sit inline, and a
                # finding must not be what copies one into a log.
                snippet=Redactor.mask(snippet.strip()[:200]),
            ),
            remediation=policy.remediation,
            explanation=Explanation(summary=policy.title, matched_rule=policy.id),
            risk=ctx.scorer.score(
                policy.severity,
                policy.confidence,
                ScoringContext(capabilities=frozenset()),
            ),
            detector=self.id,
            references=policy.references,
        )


__all__ = [
    "Block",
    "IacDetector",
    "IacPolicy",
    "blocks_for",
    "cloudformation_blocks",
    "compose_services",
    "kubernetes_blocks",
    "terraform_blocks",
]
