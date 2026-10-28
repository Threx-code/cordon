"""A configuration rule: what it matches, in which files, and what makes a match worse or excused.

Every CI, container and infrastructure rule is one of these: a pattern over the files named by its
paths, with the aggravations that raise it and the mitigations that withdraw it, and the proximity
of two patterns a rule can require.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    from collections.abc import Callable


_BOM_ANCHOR = "(?:^(?:\ufeff)?)"


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
    #: three bytes in front of its first line, a rule anchored there with `^` does not
    #: match, and the finding is simply not reported. The optional
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

    references: tuple[str, ...] = ()
    """Where this rule's claim is written down by somebody else.

    See `core.references`. Carried on the rule rather than looked up by id, so
    a rule added here arrives with its authority or visibly without one."""

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

    enclosing_key: tuple[bytes, ...] = ()
    """The YAML keys whose block this rule's match has to sit in.

    Some values mean different things depending on what reads them, and in YAML
    that is which mapping they belong to rather than what is near them. The case
    that prompted it: `${{ toJSON(secrets) }}` under `env:` puts every secret the
    job holds into a command's environment, and the same line under `with:`
    passes them as an input to a reusable workflow -- which is how a composite
    action is given a credential at all, because it cannot read the context
    itself. `Azure/bicep-registry-modules` writes the second in three workflows
    and was reported for the first.

    A proximity window cannot separate them: they are written identically and
    sit one line apart. Read from the file's indentation instead, by
    `_enclosing_keys`, which is also what keeps the pattern inside the repeat
    limits the rule loader enforces on everyone.

    Empty means the rule does not care, which is every other rule here."""

    aggravation: re.Pattern[bytes] | None = None
    """What, near the match, makes the shape worth its declared severity; without it the
    finding is recorded at LOW.

    The inverse of `mitigation`, for a rule whose shape is mostly benign and only sometimes
    the attack. `SUSPECT.CI.SECRET_EGRESS.001` is the case: a named secret beside `curl` is
    how pipelines publish, and fired in 31% of 535 repositories; what makes it worth a
    reviewer's time is a destination nobody publishes to -- a paste site, a tunnel, a
    webhook catcher, a bare IP address, a raw socket."""

    aggravation_in_file: bool = False
    """Look for `aggravation` anywhere in the file rather than near the match: a workflow's
    trigger is declared once at the top and decides what every job in it can be made to do."""
    require_aggravation: bool = False
    """Report only a match whose window HAS the aggravation; one without it is not this rule's
    claim at all. `MALWARE.CI.SECRET_TO_DROP_POINT.001` is the case: a secret sent somewhere is
    `SUSPECT.CI.SECRET_EGRESS.001`; a secret sent to a bare IP or a paste site is theft."""
    one_command: bool = False
    """With `require_aggravation`: the match and its aggravation must be one shell command, not
    merely one step. A secret written to a file in one command and a request made in the next are
    two acts; only the publishing shape spans them."""
    confirm: Callable[[re.Pattern[bytes], bytes, bytes], bool] | None = None
    """With `require_aggravation`: decides, from (aggravation, window, whole file), whether the
    window really has it, where a regex search alone cannot -- `DropPoint.sends_to_one` resolves
    which addresses are the job's own and which secrets belong to the service receiving them."""

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

    outbound_exempt: bool = False
    """Drop a match whose own block is a rule for outbound traffic. See
    `ConfigDetector._is_outbound`: a rule "from 0.0.0.0/0" is about where traffic comes from,
    and an egress rule names where it may go."""

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


class PatternProximity:
    """Two patterns near each other in a file."""

    @staticmethod
    def _near(first: str, second: str, window: int = 400) -> str:
        """Two patterns within `window` characters of each other, in either order.

        Proximity in one direction is not a rule, it is half of one.
        `curl -d "$TOKEN"` and `TOKEN=$SECRET` followed by `curl -d "$TOKEN"` are
        the same step doing the same thing, and a pattern that only reads forwards
        catches whichever half the author happened to write second.

        The window is what keeps this a claim about one step rather than about a
        file: a pipeline that uses a secret in one job and calls curl in an
        unrelated one is not this.

        Both halves are grouped before they are joined. Interpolated raw, an
        argument that is itself an alternation loses to the `|` this adds: `A|B`
        near `S` compiled as "A, or B near S, or S near A, or B", so the first
        alternative matched on its own and the proximity requirement applied to
        nothing. Callers that happened to pass a parenthesised pattern were
        unaffected, which is why it held until one did not.
        """
        first, second = f"(?:{first})", f"(?:{second})"
        return f"(?:{first}[\\s\\S]{{0,{window}}}?{second}|{second}[\\s\\S]{{0,{window}}}?{first})"


__all__ = ["ConfigRule", "PatternProximity"]
