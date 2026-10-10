"""Secrets in git history, and asking a credential's issuer whether it still works (G11).

Two additions to the secret detector, both opt-in:

`scan --history` reads every blob history still holds that the tree no longer does, through the
same detector and with the same hash-only evidence. Each distinct credential is reported once,
at the oldest commit that introduced it, because the same token in fifty historical revisions of
a file is one exposure, not fifty.

`scan --verify-secrets --online` asks the issuer of each distinct provider credential whether it
is valid, with a read-only call to that issuer's own API and nowhere else. The value is sent to
the issuer it belongs to, which already has it, and to no one else: not to Cordon, not to a
proxy, never logged and never written into a finding. A credential the issuer accepts is
reported as live, at critical; one it rejects is reported as revoked, at info, so triage can
start with what still works. Shapes whose only check would have a side effect -- a Slack
webhook can only be tested by posting to it -- are not checked, and say so.
"""

from __future__ import annotations

import base64
import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import ClassVar

from cordon_scanner.core import references
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Category, Confidence, Finding, Location, Severity
from cordon_scanner.detect.catalogue import DeclaredRule

LIVE_RULE = "SECRET.LIVE.001"
REVOKED_RULE = "SECRET.LIVENESS.REJECTED.001"
HISTORY_INCOMPLETE_RULE = "OPERATIONAL.SECRET_HISTORY.INCOMPLETE.001"
UNCHECKED_RULE = "OPERATIONAL.SECRET_LIVENESS.UNCHECKED.001"
MAX_VERIFICATIONS = 50
TIMEOUT_SECONDS = 6.0


class SecretHistoryRules:
    @staticmethod
    def declared() -> list[DeclaredRule]:
        return [
            DeclaredRule(
                id=LIVE_RULE,
                title="The credential's issuer confirms it still works",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector="secrets",
                message=(
                    "A committed credential was sent to its own issuer with --verify-secrets, and the "
                    "issuer accepted it. Whoever has read this repository, or any clone of it, can use it now."
                ),
                remediation="Revoke it at the issuer first, then rotate, then remove it from history.",
                references=(references.HARDCODED_CREDENTIALS,),
            ),
            DeclaredRule(
                id=REVOKED_RULE,
                title="The credential's issuer rejects it",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector="secrets",
                message=(
                    "A committed credential was sent to its own issuer with --verify-secrets, and the "
                    "issuer rejected it: revoked, expired or never valid. It still belongs out of the tree."
                ),
                remediation="Remove it from the tree; confirm the rejection was revocation, not a typo in a live key.",
                references=(references.HARDCODED_CREDENTIALS,),
            ),
            DeclaredRule(
                id=HISTORY_INCOMPLETE_RULE,
                title="Part of git history was not read for secrets",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector="secrets",
                message="The history pass stopped at a bound; the blobs past it were not read and are not clean.",
                remediation="Raise the bound or scan history in a dedicated job with a longer budget.",
                references=(references.HARDCODED_CREDENTIALS,),
            ),
            DeclaredRule(
                id=UNCHECKED_RULE,
                title="Some credentials could not be checked with their issuer",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector="secrets",
                message="These credentials were found but their issuer was not asked, or did not answer.",
                remediation="Check them by hand at the issuer, or rerun when the issuer is reachable.",
                references=(references.HARDCODED_CREDENTIALS,),
            ),
        ]


class HistorySecretScan:
    """The history pass: removed blobs through the secret detector, one finding per credential."""

    def __init__(self, root: Path, config, rules) -> None:  # type: ignore[no-untyped-def]
        self.root = root
        self.config = config
        self.rules = rules
        self.blob_contents: dict[tuple[str, str], bytes] = {}

    def run(self) -> list[Finding]:
        from cordon_scanner.detect.base import FileUnit, ScanContext
        from cordon_scanner.detect.secrets import SecretDetector
        from cordon_scanner.langs.registry import LanguageRegistry
        from cordon_scanner.sources.git import GitRepository
        from cordon_scanner.sources.history import GitHistory

        info = GitRepository.discover(self.root)
        if info is None:
            return []
        history = GitHistory(GitRepository(info.root))
        detector = SecretDetector()
        ctx = ScanContext(config=self.config, rules=self.rules)
        earliest: dict[tuple[str, str], tuple[Finding, str]] = {}
        from cordon_scanner.detect.secrets import PROVIDER_PATTERNS

        # From a binary's strings, only a credential with a provider's own shape (`ghp_`, `AKIA`,
        # `xoxb-`): a printable run in a compiled file or a database page can look like anything
        # an entropy rule measures, and nothing like a fixed provider prefix by chance.
        provider = frozenset(p.rule_id for p in PROVIDER_PATTERNS)
        for blob in history.blobs():
            for path, data, from_binary in self._readable(blob.path, blob.data):
                content = FileContent.from_bytes(path, data)
                unit = FileUnit(content=content, language=LanguageRegistry.identify_language(path))
                for finding in detector.inspect(unit, ctx):
                    if not finding.rule_id.startswith("SECRET."):
                        continue
                    if from_binary and finding.rule_id not in provider:
                        continue
                    key = (finding.rule_id, finding.evidence.match_hash)
                    if key not in earliest:
                        earliest[key] = (finding, blob.object_id)
                        self.blob_contents[key] = data
        findings = [
            self._place(history, finding, object_id) for finding, object_id in earliest.values()
        ]
        coverage = history.coverage
        if not coverage.complete:
            findings.append(self._incomplete(coverage))
        return findings

    #: Media and font formats: compressed pixels and glyphs, nothing a credential is kept in.
    MEDIA = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".tiff",
        ".avif",
        ".heic",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".mkv",
        ".webm",
        ".wav",
        ".flac",
        ".ogg",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
    )

    def _readable(self, path: str, data: bytes) -> list[tuple[str, bytes, bool]]:
        """What of one historical blob the secret rules can read.

        Text as it is. An archive opened with the same bounded reader the tree uses, each member
        named `archive!member`, a binary member as its strings. Any other binary -- a database
        dump, a compiled file, a keystore -- as its printable strings: a credential in a committed
        `.sqlite` or `.pyc` is the same credential.
        """
        from cordon_scanner.archive.safe import ArchiveReader
        from cordon_scanner.images.binmeta import BinaryStrings

        def as_text(name: str, payload: bytes) -> list[tuple[str, bytes, bool]]:
            if name.lower().endswith(self.MEDIA):
                return []
            if FileContent.from_bytes(name, payload).is_binary:
                return [(name, BinaryStrings.extract(payload, limit=8 << 20)[0], True)]
            return [(name, payload, False)]

        if ArchiveReader.is_archive(path):
            try:
                members = list(
                    ArchiveReader.walk_archive(data, path=path, limits=self.config.limits)
                )
            except Exception:  # a malformed archive is read as bytes instead
                members = []
            if members:
                return [item for name, payload in members for item in as_text(name, payload)]
        return as_text(path, data)

    @staticmethod
    def _place(history, finding: Finding, object_id: str) -> Finding:  # type: ignore[no-untyped-def]
        introduced = history.introduced_by(object_id)
        commit, when = introduced if introduced else ("unknown", "")
        where = f"commit {commit[:12]}" + (f" ({when[:10]})" if when else "")
        return replace(
            finding,
            message=(
                f"Removed from the working tree, still in git history: introduced in {where}. "
                f"Every clone and fork holds it. {finding.message}"
            ),
            location=replace(finding.location, symbol=f"history:{commit[:12]}"),
            fingerprint="",
        )

    @staticmethod
    def _incomplete(coverage) -> Finding:  # type: ignore[no-untyped-def]
        from cordon_scanner.detect.secrets import SecretDetector

        parts = []
        if coverage.skipped_over_ceiling:
            parts.append(
                f"{coverage.skipped_over_ceiling} blob(s) past the {coverage.considered - coverage.skipped_over_ceiling}-blob ceiling"
            )
        if coverage.skipped_large:
            parts.append(f"{coverage.skipped_large} blob(s) over the size limit")
        if coverage.stopped_for_time:
            parts.append("the rest after the time budget ran out")
        return SecretDetector().operational(
            path=".git",
            rule_id=HISTORY_INCOMPLETE_RULE,
            message=f"Read {coverage.read} of {coverage.considered} historical blob(s); not read: {', '.join(parts)}.",
            degrades_coverage=True,
        )


@dataclass(frozen=True, slots=True)
class IssuerCheck:
    """One issuer's read-only validity check: request builder and how to read the answer."""

    host: str
    request: Callable[[str], urllib.request.Request]
    accepted: Callable[[int, bytes], bool | None]
    """True: valid. False: rejected. None: the answer said neither."""


class SecretLiveness:
    """Ask each distinct credential's own issuer whether it works. Opt-in, read-only, bounded."""

    @staticmethod
    def _bearer(
        url: str, token: str, method: str = "GET", extra: dict[str, str] | None = None
    ) -> urllib.request.Request:
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "cordon-scanner verify-secrets",
            **(extra or {}),
        }
        return urllib.request.Request(url, headers=headers, method=method)  # noqa: S310 - fixed https URLs below

    @staticmethod
    def _status(valid: int, *invalid: int) -> Callable[[int, bytes], bool | None]:
        def read(status: int, _body: bytes) -> bool | None:
            if status == valid:
                return True
            if status in invalid:
                return False
            return None

        return read

    @staticmethod
    def _slack(status: int, body: bytes) -> bool | None:
        try:
            answer = json.loads(body)
        except ValueError:
            return None
        if not isinstance(answer, dict):
            return None
        if answer.get("ok") is True:
            return True
        return (
            False
            if answer.get("error")
            in ("invalid_auth", "account_inactive", "token_revoked", "not_authed")
            else None
        )

    ISSUERS: ClassVar[dict[str, IssuerCheck]] = {}

    @classmethod
    def issuers(cls) -> dict[str, IssuerCheck]:
        if not cls.ISSUERS:
            cls.ISSUERS.update(
                {
                    "SECRET.GITHUB.TOKEN.001": IssuerCheck(
                        "api.github.com",
                        lambda t: cls._bearer("https://api.github.com/user", t),
                        cls._status(200, 401),
                    ),
                    "SECRET.GITLAB.TOKEN.001": IssuerCheck(
                        "gitlab.com",
                        lambda t: urllib.request.Request(
                            "https://gitlab.com/api/v4/personal_access_tokens/self",
                            headers={
                                "PRIVATE-TOKEN": t,
                                "User-Agent": "cordon-scanner verify-secrets",
                            },
                        ),
                        cls._status(200, 401),
                    ),
                    "SECRET.SLACK.TOKEN.001": IssuerCheck(
                        "slack.com",
                        lambda t: cls._bearer("https://slack.com/api/auth.test", t, "POST"),
                        cls._slack,
                    ),
                    "SECRET.SLACK.APP_TOKEN.001": IssuerCheck(
                        "slack.com",
                        lambda t: cls._bearer("https://slack.com/api/auth.test", t, "POST"),
                        cls._slack,
                    ),
                    "SECRET.NPM.TOKEN.001": IssuerCheck(
                        "registry.npmjs.org",
                        lambda t: cls._bearer("https://registry.npmjs.org/-/whoami", t),
                        cls._status(200, 401, 403),
                    ),
                    "SECRET.OPENAI.KEY.001": IssuerCheck(
                        "api.openai.com",
                        lambda t: cls._bearer("https://api.openai.com/v1/models", t),
                        cls._status(200, 401),
                    ),
                    "SECRET.ANTHROPIC.KEY.001": IssuerCheck(
                        "api.anthropic.com",
                        lambda t: urllib.request.Request(
                            "https://api.anthropic.com/v1/models",
                            headers={
                                "x-api-key": t,
                                "anthropic-version": "2023-06-01",
                                "User-Agent": "cordon-scanner verify-secrets",
                            },
                        ),
                        cls._status(200, 401),
                    ),
                    "SECRET.STRIPE.KEY.001": IssuerCheck(
                        "api.stripe.com",
                        lambda t: urllib.request.Request(
                            "https://api.stripe.com/v1/balance",
                            headers={
                                "Authorization": "Basic "
                                + base64.b64encode(f"{t}:".encode()).decode(),
                                "User-Agent": "cordon-scanner verify-secrets",
                            },
                        ),
                        cls._status(200, 401),
                    ),
                }
            )
        return cls.ISSUERS

    #: Found shapes whose only check would change something, or need a second secret.
    NOT_CHECKABLE: ClassVar[dict[str, str]] = {
        "SECRET.SLACK.WEBHOOK.001": "the only check is posting a message to the channel",
        "SECRET.AWS.ACCESS_KEY.001": "an access key id is checkable only with its secret half",
        "SECRET.STRIPE.WEBHOOK_SECRET.001": "a webhook signing secret has no validity endpoint",
    }

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return None

    def __init__(
        self,
        opener: Callable[[urllib.request.Request], tuple[int, bytes]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.opener = opener or self._open
        self.clock = clock

    def _open(self, request: urllib.request.Request) -> tuple[int, bytes]:
        opener = urllib.request.build_opener(self._NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                return response.status, response.read(64 << 10)
        except urllib.error.HTTPError as exc:
            return exc.code, b""

    def check(self, rule_id: str, value: str) -> bool | None:
        issuer = self.issuers().get(rule_id)
        if issuer is None:
            return None
        request = issuer.request(value)
        # The value goes to its own issuer's fixed host over HTTPS, and nowhere else.
        if not request.full_url.startswith(f"https://{issuer.host}/"):
            return None
        try:
            status, body = self.opener(request)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
            return None
        return issuer.accepted(status, body)

    def verify(
        self, findings: Iterable[Finding], value_of: Callable[[Finding], str | None]
    ) -> list[Finding]:
        """New findings: live or revoked per distinct credential, plus one note for the unchecked."""
        added: list[Finding] = []
        unchecked: list[str] = []
        seen: set[tuple[str, str]] = set()
        asked = 0
        for finding in findings:
            key = (finding.rule_id, finding.evidence.match_hash)
            if (
                not finding.rule_id.startswith("SECRET.")
                or key in seen
                or finding.rule_id in (LIVE_RULE, REVOKED_RULE)
            ):
                continue
            seen.add(key)
            if finding.rule_id in self.NOT_CHECKABLE:
                unchecked.append(f"{finding.rule_id} ({self.NOT_CHECKABLE[finding.rule_id]})")
                continue
            if finding.rule_id not in self.issuers():
                continue
            if asked >= MAX_VERIFICATIONS:
                unchecked.append(f"{finding.rule_id} (past the {MAX_VERIFICATIONS}-check ceiling)")
                continue
            value = value_of(finding)
            if not value:
                unchecked.append(f"{finding.rule_id} (value not recoverable)")
                continue
            asked += 1
            verdict = self.check(finding.rule_id, value)
            value = ""
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock()))
            if verdict is True:
                added.append(
                    self._derived(
                        finding,
                        LIVE_RULE,
                        Severity.CRITICAL,
                        f"Its issuer accepted it at {stamp}: this credential works now. ",
                    )
                )
            elif verdict is False:
                added.append(
                    self._derived(
                        finding, REVOKED_RULE, Severity.INFO, f"Its issuer rejected it at {stamp}. "
                    )
                )
            else:
                unchecked.append(f"{finding.rule_id} (the issuer did not give a clear answer)")
        if unchecked:
            from cordon_scanner.detect.secrets import SecretDetector

            added.append(
                SecretDetector().operational(
                    path=".",
                    rule_id=UNCHECKED_RULE,
                    message=f"{len(unchecked)} credential(s) were not checked with their issuer: {'; '.join(unchecked[:10])}.",
                )
            )
        return added

    @staticmethod
    def _derived(finding: Finding, rule_id: str, severity: Severity, lead: str) -> Finding:
        return replace(
            finding,
            rule_id=rule_id,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            message=lead + finding.message,
            threat_domain=None,
            attack_category=None,
            fingerprint="",
        )


class SecretValues:
    """Recover a finding's matched value, for one issuer check, from bytes still in hand.

    The value is re-read at the finding's byte span and accepted only if it hashes to the
    finding's own evidence hash, so a file that changed since the scan, or a span that does not
    hold the credential, yields nothing rather than a wrong value sent to an issuer.
    """

    def __init__(self, root: Path, history: dict[tuple[str, str], bytes] | None = None) -> None:
        self.root = root.resolve()
        self.history = history or {}

    def __call__(self, finding: Finding) -> str | None:
        from cordon_scanner.core.models import Evidence

        location: Location = finding.location
        if location.byte_start is None or location.byte_end is None:
            return None
        if (location.symbol or "").startswith("history:"):
            raw = self.history.get((finding.rule_id, finding.evidence.match_hash))
        else:
            path = (self.root / location.path).resolve()
            if self.root not in path.parents or not path.is_file():
                return None
            raw = path.read_bytes()
        if raw is None:
            return None
        span = raw[location.byte_start : location.byte_end]
        if not span or Evidence.secret_hash(span) != finding.evidence.match_hash:
            return None
        return span.decode("utf-8", "replace")
