"""Where code sends what it sends: the destination capabilities a file's text shows -- an
out-of-band interaction service, a drop point, a public IP address written as a URL."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.documentation import DocumentationSpans
from cordon_scanner.detect.code.addresses import PublicAddress
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.text_position import TextPosition
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.text.comments import SourceComments

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class DestinationLabels:
    """The destination capabilities of a file: what its URLs and hosts say about where data goes."""

    DROP_POINT_RULE = "INTEL.EGRESS.DROP_POINT.001"
    """Rule id for egress to a destination that is itself informative.

    Named so composites can refer to it. It is a capability label rather than a
    finding, like the AST tier's, and it exists because the capability model
    deliberately cannot tell one outbound request from another -- posting to a
    metrics endpoint and posting to a Discord webhook are both `egress`.
    """

    INTERACTION_RULE = "INTEL.EGRESS.INTERACTION.001"
    """Egress to an out-of-band interaction service. See `intel.hosts.INTERACTION_HOSTS`."""

    #: A line that binds a value to one name: `URL = ...`, `const URL = ...`, `URL: str = ...`.
    _BINDING: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:export\s+)?(?:(?:const|let|var|final)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=(?!=)"
    )

    @classmethod
    def sent_at_import(
        cls,
        hits: list[CapabilityHit],
        source: str | None = None,
        sent_elsewhere: frozenset[str] = frozenset(),
    ) -> list[CapabilityHit]:
        """The hits, less a destination label on a line where nothing is sent: what import makes
        of a URL written as a constant or passed to a constructor is a destination named, not a
        request. A label on a request's own line (`urlopen("http://1.2.3.4", data)`) stays, and so
        does one whose line binds the URL to a name that a sending line uses (`HOOK = "<drop
        point>"` then `requests.post(HOOK, ...)`): the request goes there, from another line
        (sf_th_requests 0.1.0 lost INSTALL_CALLBACK without it). `sent_elsewhere` are the names
        this file binds that another file of the package imports and sends (`SentNames`): the
        hook written in `__init__.py` and posted from the modules that import it (loveclose 0.0.1,
        whose `__init__.py` sends nothing itself)."""
        labels = (cls.DROP_POINT_RULE, cls.INTERACTION_RULE)
        sending = {
            hit.line
            for hit in hits
            if hit.capability is Capability.EGRESS and hit.rule_id not in labels
        }
        bound = cls._bound_to_a_send(
            {hit.line for hit in hits if hit.rule_id in labels} - sending,
            sending,
            source,
            sent_elsewhere,
        )
        return [
            hit
            for hit in hits
            if hit.rule_id not in labels or hit.line in sending or hit.line in bound
        ]

    @classmethod
    def _bound_to_a_send(
        cls,
        label_lines: set[int],
        sending: set[int],
        source: str | None,
        sent_elsewhere: frozenset[str] = frozenset(),
    ) -> set[int]:
        """Label lines that bind their value to a name a sending line uses, as a whole word, or
        to a name another file of the package imports and sends."""
        if not source or not label_lines or not (sending or sent_elsewhere):
            return set()
        lines = source.splitlines()
        if sending:
            sending = sending | cls._helper_send_lines(source, sending)
        sent_text = [lines[n - 1] for n in sending if 0 < n <= len(lines)]
        kept: set[int] = set()
        for line in label_lines:
            if not 0 < line <= len(lines):
                continue
            binding = cls._BINDING.match(lines[line - 1])
            if binding is None:
                continue
            if binding.group(1) in sent_elsewhere:
                kept.add(line)
                continue
            name = re.compile(rf"(?<![\w$.]){re.escape(binding.group(1))}(?![\w$])")
            if any(name.search(text) for text in sent_text):
                kept.add(line)
        return kept

    #: Rounds of helper followed: `send_to_beacon` -> `post` -> `_make_request` -> `urlopen`.
    HELPER_HOPS: ClassVar[int] = 3

    @classmethod
    def _helper_send_lines(cls, source: str, sending: set[int]) -> set[int]:
        """Lines that call one of the file's own functions whose body sends, directly or through
        another such function (sf_th_requests 0.1.0: `post(BEACON_URL, creds)` -> `_make_request`
        -> `urlopen`, run at import). Python only; a file that does not parse adds nothing."""
        import ast

        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            # S2: a file that does not parse is reported as SOURCE.UNPARSED where it runs (its own
            # analyser); here it keeps the line-only reading of `_bound_to_a_send`, nothing more.
            return set()
        functions = list(PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef))

        def called(node: ast.Call) -> str | None:
            func = node.func
            if isinstance(func, ast.Name):
                return func.id
            return func.attr if isinstance(func, ast.Attribute) else None

        senders = {
            f.name
            for f in functions
            if any(f.lineno <= n <= (f.end_lineno or f.lineno) for n in sending)
        }
        for _ in range(cls.HELPER_HOPS):
            grown = senders | {
                f.name
                for f in functions
                if any(called(c) in senders for c in PythonSyntax.within(f, ast.Call))
            }
            if grown == senders:
                break
            senders = grown
        return {c.lineno for c in PythonSyntax.of(tree, ast.Call) if called(c) in senders}

    @classmethod
    def destination_capabilities(
        cls, content: FileContent, language: str | None = None, *, notifier_exempt: bool = True
    ) -> list[CapabilityHit]:
        """Egress to a destination that means something on its own.

        Webhook ingest URLs, anonymous paste and file-drop services, and
        out-of-band interaction hosts. None of these is a finding by itself --
        software does post to webhooks -- but each is a place with no reason to
        appear in a build, an install script or a library, so it raises what an
        outbound request in that file is worth.

        The host list lives in `analysis/shared/destinations.py` rather than in a pattern pack.
        A pack would have to restate it, and a restated blocklist drifts, which
        is worse than a short one because it still looks maintained.
        """
        from cordon_scanner.analysis.shared.destinations import Destinations

        raw = content.raw
        literal_ip = cls.public_ip_url(content, language)

        # A substring prefilter, for the same reason the rule engine has one:
        # the alternation over every host is around eight hundred bytes and
        # cost roughly five milliseconds per file when it ran unconditionally,
        # which was enough to put a large repository over its latency budget by
        # itself. Almost every file is rejected here without a regex running.
        if not Destinations.could_match(raw):
            return literal_ip

        # Skipping documentation, which names a host without contacting one.
        # This searched the raw bytes and took the first hit, so a module whose
        # opening paragraph explains what it drives was read as driving it --
        # see `analysis.shared.documentation.DocumentationSpans.of` for the case that found it. The
        # later occurrences are still considered, because the first being prose
        # says nothing about the rest of the file.

        # The spans are worked out at the first candidate, not before: the prefilter passes far
        # more files than the matcher finds a host in, and on those the spans were most of the
        # time (a 4 MB API model: 1.6 s of spans, then no candidate; measured 2026-10-31).
        # Block comments are asked of `FileContent.in_block_comment`, indexed once per file.
        ignore: tuple[tuple[int, int], ...] | None = None

        match = None
        for candidate in Destinations.candidates(raw):
            if ignore is None:
                ignore = DocumentationSpans.of(raw, language)
            offset = candidate.start()
            if SourceComments.inside_spans(ignore, offset) or content.in_block_comment(
                offset, language
            ):
                continue
            if TextPosition.is_comment(content, offset, language):
                continue
            if notifier_exempt and cls._token_from_variable(raw, candidate):
                continue
            match = candidate
            break
        if match is None:
            return literal_ip

        found = [
            CapabilityHit(
                capability=Capability.EGRESS,
                rule_id=cls.DROP_POINT_RULE,
                byte_start=match.start(),
                byte_end=match.end(),
                line=content.line_of(match.start()),
            )
        ]
        from cordon_scanner.analysis.shared.destinations import Destinations

        host = match.group(0).decode("utf-8", "replace").split("//")[-1].split("/")[0]
        if Destinations.is_interaction_host(host):
            found.append(
                CapabilityHit(
                    capability=Capability.EGRESS,
                    rule_id=cls.INTERACTION_RULE,
                    byte_start=match.start(),
                    byte_end=match.end(),
                    line=content.line_of(match.start()),
                )
            )
        return found

    #: A Telegram bot token as it is written in a file: the bot's numeric id, a colon, thirty-five characters.
    _TELEGRAM_TOKEN = re.compile(rb"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")

    @classmethod
    def _token_from_variable(cls, raw: bytes, candidate: re.Match[bytes]) -> bool:
        """Whether a bot API URL takes its token from a variable: `bot${token}`, `bot{token}`, `bot%s`.

        The bot URL is a drop point because malware posts to it with a token it carries. A client that
        asks its user for the token is a notifier; it is reported as a drop point only when a literal
        token is written somewhere in the same file."""
        if not candidate.group(0).lower().endswith(b"api.telegram.org/bot"):
            return False
        following = raw[candidate.end() : candidate.end() + 1]
        if not following or following.isdigit():
            return False
        return cls._TELEGRAM_TOKEN.search(raw) is None

    _IP_URL = re.compile(
        rb"\bhttps?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?(?:/|[\"'\s]|$)"
    )

    # The same address given as a host rather than inside a URL: `const TARGET_HOST =
    # '154.57.164.64'` handed to `http.request({hostname: TARGET_HOST})`, or a socket's
    # `connect(4444, '154.57.164.64')`. A bare four-part string is as often a version number,
    # so it counts only where the line names it as a host.
    # `\b(?=[a-z_]*host)[a-z_]*+` is `\b[a-z_]*host[a-z_]*`: what follows cannot be `[a-z_]`, so the
    # word is always taken whole, and asking first whether it holds `host` reads it once instead of
    # once per `host` in it. The blanks of `connect(` are taken once (review 98, 27-PERFORMANCE).
    _IP_HOST = re.compile(
        rb"(?i)(?:\b(?=[a-z_]*host)[a-z_]*+[\"']?\s*[:=]|\b(?:connect|createConnection)\(\s*+(?:\d{1,5}\s*,\s*+)?)"
        rb"\s*[\"'](\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})[\"']"
    )

    # What every match of each must contain, as a pattern the regex engine scans for fast (a
    # literal or a two-character class first, where the full patterns open on `\b`): over ten
    # thousand files of ordinary packages the two ran on every one, 7.8 s for five files with any
    # match, and 1.2 s gated, with the same matches.
    _IP_URL_GATE = re.compile(rb"https?://\d")

    _IP_HOST_GATE = re.compile(rb"[\"']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\"']")

    # Public resolvers, which network checks and DNS clients name as hosts all the time, and
    # the made-up addresses examples and fixtures use (`"host": "1.2.3.4"`): public on paper,
    # reached by nobody.
    _RESOLVERS: ClassVar[frozenset[tuple[int, ...]]] = frozenset(
        {
            (1, 1, 1, 1), (1, 0, 0, 1), (8, 8, 8, 8), (8, 8, 4, 4), (9, 9, 9, 9),
            (208, 67, 222, 222), (1, 2, 3, 4), (4, 3, 2, 1), (5, 6, 7, 8), (12, 34, 56, 78),
            (11, 22, 33, 44), (123, 123, 123, 123), (123, 45, 67, 89),
        }
    )  # fmt: skip

    @classmethod
    def public_ip_url(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """A URL, or a host setting, whose host is a literal public IPv4 address.

        Services are reached by name; a payload posting the environment to
        `http://54.242.228.151:8090/` does not have one. Loopback, private, link-local -- the
        cloud metadata service at 169.254.169.254 -- and the documentation ranges are ordinary
        in code and tests and are not counted.
        """

        ignore: tuple[tuple[int, int], ...] | None = None
        raw = content.raw
        matches = [
            *(cls._IP_URL.finditer(raw) if cls._IP_URL_GATE.search(raw) else ()),
            *(cls._IP_HOST.finditer(raw) if cls._IP_HOST_GATE.search(raw) else ()),
        ]
        for match in sorted(matches, key=lambda m: m.start()):
            octets = [int(part) for part in match.groups()]
            if any(o > 255 for o in octets) or not PublicAddress.is_public(octets):
                continue
            if tuple(octets) in cls._RESOLVERS:
                continue
            # Docstrings are worked out only once a public address is found: almost no file has
            # one, and the spans mean parsing the file.
            if ignore is None:
                ignore = DocumentationSpans.of(content.raw, language)
            if SourceComments.inside_spans(ignore, match.start()) or TextPosition.is_comment(
                content, match.start(), language
            ):
                continue
            return [
                CapabilityHit(
                    capability=Capability.EGRESS,
                    rule_id=cls.DROP_POINT_RULE,
                    byte_start=match.start(),
                    byte_end=match.end(),
                    line=content.line_of(match.start()),
                )
            ]
        return []


__all__ = ["DestinationLabels"]
