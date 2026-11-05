"""The data model of infrastructure-as-code checks: a resource block, and one policy over it.

Here rather than in `iac`, the detector that runs them, so the policy tables (cloud, workload,
plaintext, curated, generated) import the model and the detector imports the tables, in one
direction (review 27, F3: the tables and the detector imported each other).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cordon_scanner.foundation.models import Category, Confidence, Severity


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

    body_start: int = -1
    """Offset of `body[0]` in the file, or -1 when the body is not a slice of it.

    A finding has to point at the line the reader has to change, and for a
    `forbid` policy that is the attribute rather than the resource. The match
    offset is relative to `body`, so mapping it back to the file needs to know
    where `body` begins -- which for Terraform and Bicep is after the opening
    brace and not at `start`, a difference of a whole header line. Reported
    against Azure's quickstart templates, `publicNetworkAccess: 'Enabled'` on
    line 20 was reported on line 15, and every `forbid` finding in those two
    formats was out by the length of its own header.

    JSON formats re-serialise the parsed resource rather than slicing the file,
    because a CloudFormation or ARM template's structure is what identifies a
    resource and the text is not addressable that way. There is no offset to map
    back, so those keep pointing at the resource's own declaration, which is
    true and is the line a reader starts at."""


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
            # A data source is read only by a policy that names it (`data:external`): the
            # wildcard policies were written for resources, and a `require` among them would
            # demand a resource's attribute of every data source.
            if kind.startswith("data:") and not wanted.startswith("data:"):
                continue
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


__all__ = ["Block", "IacPolicy"]
