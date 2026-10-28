"""Credentials written in pieces or encodings: a value assembled from fragments joined at run time, a
value folded across lines, a value base64- or hex-encoded -- each put back together, or decoded, so
the provider patterns can be tried on what the program will actually hold. One finding per
credential, however many forms of it a file contains."""

from __future__ import annotations

import base64
import binascii
import re
from typing import TYPE_CHECKING

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.secrets.patterns import (
    ASSIGNMENT,
    CREDENTIAL_NAME,
    MIN_KEY_BODY,
    PROVIDER_PATTERNS,
    ROTATE,
    SecretPattern,
)
from cordon_scanner.detect.secrets.values import SecretValues
from cordon_scanner.foundation.models import (
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.content import FileContent

MIN_ASSEMBLED_ENTROPY = 4.0
"""Entropy floor for a value built by concatenation.

Higher than the floor for a plain assignment, and deliberately so. Assembly is
also how ordinary code builds paths, messages and URLs, so the bar for calling
one a credential on entropy alone has to sit above anything a human wrote by
hand. A value with a known credential prefix skips this entirely -- the prefix
is the evidence."""

MIN_ASSEMBLED_LENGTH = 20
"""How long an assembled value must be before entropy is consulted.

Shannon entropy over a short sample is bounded by log2 of its length, so a
15-character value cannot reach the floor above whatever it contains. Testing
it would only produce a number that means nothing."""

CREDENTIAL_PREFIXES = (
    b"AKIA",
    b"ASIA",
    b"ghp_",
    b"gho_",
    b"ghu_",
    b"ghs_",
    b"ghr_",
    b"github_pat_",
    b"glpat-",
    b"xox",
    b"sk_live_",
    b"sk-",
    b"npm_",
    b"AIza",
    # Private key headers only. `-----BEGIN` also opens a CERTIFICATE, which
    # is public by design and is committed on purpose in every TLS test suite
    # -- it produced thirty-nine findings in OkHttp alone.
    b"-----BEGIN PRIVATE KEY",
    b"-----BEGIN RSA PRIVATE KEY",
    b"-----BEGIN EC PRIVATE KEY",
    b"-----BEGIN DSA PRIVATE KEY",
    b"-----BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN PGP PRIVATE KEY",
    b"-----BEGIN ENCRYPTED PRIVATE KEY",
)
"""Prefixes that exist to make a credential format recognisable.

A value starting with one of these is a credential regardless of what its
entropy says, which matters because a padded or low-variety token sits below any
sensible entropy floor while still being live."""

MIN_CHARACTER_CLASSES = 2
"""How many of {lower, upper, digit, symbol} a value must use.

Generated key material almost always mixes at least two. A dictionary word or a
repeated filler string uses one, and those are what the entropy floor was
carrying alone."""

_WHITESPACE = re.compile(rb"\s")
"""Any space in a value.

Separates prose and SQL from key material better than entropy does at these
lengths, because a generated credential is a single token by construction."""


class SecretAssembly:
    """Putting a credential back together from the pieces and encodings it is written in."""

    @staticmethod
    def one_per_credential(findings: list[Finding]) -> list[Finding]:
        """Collapse findings of the same rule over overlapping bytes.

        Deduplication inside each path is by the hash of the matched VALUE, and two
        paths that match different slices of one credential do not share it. Celery's
        test keypairs came back eight times, and two of those were the same key
        reported twice: spans [158, 199] and [168, 200] on the same line, one from the
        provider pattern matching the PEM header and one from the assembled-literal
        path folding the Python triple-quoted string around it. Different bytes,
        different hash, same key, and nothing in the report to tell a reader that
        from two keys.

        The PEM header is named rather than written, for the same reason as above.

        A post-filter rather than a check inside each path, because the duplication is
        BETWEEN paths and a per-path guard cannot see across them -- which is how the
        first attempt at this missed it entirely.

        The widest span wins. Both findings describe one credential and the longer
        match is the one that located more of it, so it is the more useful evidence to
        keep.
        """
        ordered = sorted(
            findings,
            key=lambda f: (
                f.rule_id,
                -((f.evidence.span or (0, 0))[1] - (f.evidence.span or (0, 0))[0]),
                (f.evidence.span or (0, 0))[0],
            ),
        )
        kept: list[Finding] = []
        claimed: dict[str, list[tuple[int, int]]] = {}
        for finding in ordered:
            span = finding.evidence.span
            if span is None:
                kept.append(finding)
                continue
            ranges = claimed.setdefault(finding.rule_id, [])
            if any(start < span[1] and span[0] < end for start, end in ranges):
                continue
            ranges.append(span)
            kept.append(finding)
        # Back to the order the paths produced them in, so output stays stable.
        order = {id(f): i for i, f in enumerate(findings)}
        return sorted(kept, key=lambda f: order[id(f)])

    @staticmethod
    def assembled_spec(
        value: bytes, *, assembled: bool = True, name: str | None = None
    ) -> SecretPattern | None:
        """What an assembled value is, if it is anything.

        A provider shape is decisive on its own: those prefixes exist to make
        the format recognisable, and nothing else produces them. Beyond that the
        bar is deliberately higher than for a contiguous literal, because
        assembly is also how ordinary code builds paths, messages and URLs. The
        entropy floor is the one from the audit rather than the assignment
        floor, so `"pre" + "fix" + "-" + slug` cannot reach it.
        """
        for provider in PROVIDER_PATTERNS:
            if provider.prefilter and not any(lit in value for lit in provider.prefilter):
                continue
            if provider.pattern.search(value):
                return provider

        # The prefix followed by the key, not the prefix alone: litellm declares
        # `LITELLM_VIRTUAL_KEY_PREFIX: Final = "sk-"` to test bearer tokens against.
        # A PEM armour header is decisive alone: it opens a key block.
        if any(
            value.startswith(prefix)
            and (prefix.startswith(b"-----") or len(value) - len(prefix) >= MIN_KEY_BODY)
            for prefix in CREDENTIAL_PREFIXES
        ):
            return SecretPattern(
                rule_id="SECRET.GENERIC.ASSIGNMENT.001",
                name="credential assembled from parts",
                pattern=ASSIGNMENT,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation=ROTATE,
            )

        if not assembled:
            # A plain literal, carried here only because Python joins adjacent
            # literals with no operator. The provider shapes and prefixes above
            # apply to it; the entropy heuristic below does not, because its
            # justification is that building a value from pieces is not how a
            # URL or an identifier is written -- and applied to every constant
            # it reports every long URL in the project as a credential.
            return None

        if len(value) < MIN_ASSEMBLED_LENGTH:
            return None

        if not (name and CREDENTIAL_NAME.search(name.encode("utf-8", "replace"))):
            # The contiguous path reaches this rule only through a pattern that
            # requires a credential-shaped *name*, and the assembled path
            # dropped that requirement -- so any high-entropy concatenation
            # anywhere qualified, and jQuery, Guava's cache tests and a great
            # deal of ordinary string building were reported as credentials.
            #
            # Provider shapes and known prefixes above still fire whatever the
            # name is, which is right: a GitHub token is one regardless of what
            # it was assigned to. Entropy alone is not, and needs the name to
            # mean anything.
            return None

        if _WHITESPACE.search(value):
            # Key material is one token. Entropy alone cannot tell a credential
            # from a sentence -- Shannon entropy rewards a varied alphabet, and
            # `"SELECT id, name" + " FROM packages"` scores 4.48, well above any
            # floor prose is supposed to sit below. What actually separates them
            # is that a generated secret never contains a space.
            return None

        decoded = value.decode("utf-8", errors="replace")
        if Redactor.shannon_entropy(decoded) < MIN_ASSEMBLED_ENTROPY:
            return None
        if SecretAssembly.character_classes(decoded) < MIN_CHARACTER_CLASSES:
            return None

        return SecretPattern(
            rule_id="SECRET.GENERIC.ASSIGNMENT.001",
            name="high-entropy value assembled from parts",
            pattern=ASSIGNMENT,
            severity=Severity.HIGH,
            # Assembly is the signal. A value of this entropy could be a hash or
            # an identifier, but building one out of pieces is not how either is
            # written, and it is exactly how a credential is hidden.
            confidence=Confidence.MEDIUM,
            remediation=ROTATE,
        )

    @staticmethod
    def folded_values(unit: FileUnit) -> Iterable[tuple[int, int, bytes, bool, str | None]]:
        """Concatenated string values, folded to what they evaluate to.

        Python goes through the AST, which folds `+` chains, `"".join` and
        f-strings of constants, and knows an assignment from an expression.
        Everything else -- and any Python that will not parse -- falls back to
        joining adjacent literals in the bytes, which handles the common form
        without pretending to understand the language.
        """
        content = unit.content

        # First, and unconditionally. The Python branch below returns early for
        # a file that parses, so anything yielded after it is yielded for every
        # language except the one with the best analysis -- which is where this
        # was, and why an encoded token in a `.py` was still missed after the
        # decoder existed.
        yield from SecretAssembly._decoded_values(content)

        if unit.language == "python":
            from cordon_scanner.analysis.python.pyfacts import PythonFacts

            starts = content.line_starts
            for item in PythonFacts.assembled(content.text):
                if not item.value:
                    continue
                index = min(max(item.line - 1, 0), len(starts) - 1)
                start = starts[index]
                end = starts[index + 1] if index + 1 < len(starts) else len(content.raw)
                yield (
                    start,
                    end,
                    item.value.encode("utf-8", "surrogatepass"),
                    item.assembled,
                    item.name,
                )
            if PythonFacts.parses(content.text):
                return

        for start, end, value in SecretValues.fold_concatenations(content.raw):
            # The byte fold has no name to offer. Provider shapes and prefixes
            # still apply; the entropy branch does not, which is the honest
            # consequence of not knowing what the value was called.
            yield start, end, value, True, None

    _PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\n\r"

    @staticmethod
    def _is_mostly_printable(data: bytes) -> bool:
        """Whether decoded bytes read as text rather than as a binary blob.

        Base64 decodes anything. Without this, every embedded PNG, font and
        compiled fixture in a repository would be searched for credentials,
        and the ratio is what separates "somebody hid a string here" from
        "this is an image".
        """
        printable = sum(1 for byte in data if byte in SecretAssembly._PRINTABLE)
        return printable / len(data) > 0.9

    ENCODED_BLOB = re.compile(rb"""["']([A-Za-z0-9+/]{24,4096}={0,2})["']""")

    MAX_DECODED_BLOBS = 64

    @staticmethod
    def _decoded_values(content: FileContent) -> Iterable[tuple[int, int, bytes, bool, str | None]]:
        """Credentials hidden inside a base64 literal.

        Splitting a token across a `+` was already handled -- the fold above
        evaluates it the way the interpreter does. Encoding it was not: every
        secret pattern matches a contiguous run of the credential's own
        alphabet, and base64 is a different alphabet, so

            TOKEN = base64.b64decode("Z2hwX0JCQkJCQkJC...").decode()

        committed a live GitHub token past a scanner that catches the same
        token written plainly and catches it again when split in two. One
        decode step, and the shape the pattern is built around is simply not
        present in the file.

        Yielded as NOT assembled, which is what keeps this quiet: only the
        provider shapes and the known credential prefixes apply, and those are
        decisive on their own. The entropy branch is deliberately out of reach
        -- base64 of anything scores high by construction, so admitting it here
        would report every embedded certificate, icon and test fixture in the
        world.
        """
        decoded_count = 0
        for match in SecretAssembly.ENCODED_BLOB.finditer(content.raw):
            if decoded_count >= SecretAssembly.MAX_DECODED_BLOBS:
                return
            blob = match.group(1)
            try:
                plain = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            decoded_count += 1
            if not plain or not SecretAssembly._is_mostly_printable(plain):
                continue
            yield match.start(), match.end(), plain, False, None

    @staticmethod
    def character_classes(value: str) -> int:
        """How many of {lower, upper, digit, symbol} the value uses."""
        return sum(
            (
                any(c.islower() for c in value),
                any(c.isupper() for c in value),
                any(c.isdigit() for c in value),
                any(not c.isalnum() for c in value),
            )
        )


__all__ = [
    "CREDENTIAL_PREFIXES",
    "MIN_ASSEMBLED_ENTROPY",
    "MIN_ASSEMBLED_LENGTH",
    "MIN_CHARACTER_CLASSES",
    "SecretAssembly",
]
