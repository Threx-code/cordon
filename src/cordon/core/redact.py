"""Evidence redaction.

A finding travels much further than the repository it came from. It lands in CI
logs that are retained for months, in pull-request comments visible to everyone
with read access, and in SARIF files routinely uploaded to third-party
platforms. All three are more durable and more widely readable than the source
file itself.

The failure this module prevents is specific and easy to introduce: a rule fires
*because* a line contains key material, and the tool then copies that line into
every one of those destinations. A scanner that finds a leaked secret must not
become the mechanism that spreads it.

The default is therefore to mask, and secret-category rules cannot opt out. What
survives redaction in every mode is the match hash, which is enough to compare
two scans, confirm a finding is the same artefact as last week's, and drive
deduplication -- without the value itself ever moving.
"""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING, ClassVar

from cordon.core.models import Evidence, EvidenceKind, RedactionMode

if TYPE_CHECKING:
    from cordon.core.content import FileContent


class Redactor:
    """Turns matched bytes into evidence that is safe to publish.

    Stateless, and therefore exposed as class methods rather than requiring an
    instance: redaction must not depend on anything accumulated between calls.
    Two findings over the same bytes have to redact identically no matter what
    was redacted before them, or the match hash stops identifying the artefact.

    The class exists to keep the masking passes, the thresholds they compare
    against and the mode arithmetic in one place. They are a single policy, and
    splitting them across a module makes it possible to change a threshold
    without seeing the pass that depends on it.
    """

    MASK = "[redacted]"

    MAX_SNIPPET_BYTES = 200
    """Cap on snippet length.

    A long snippet is not more informative; it is more leakage. The reader needs
    enough to recognise the construct, and the file and line to go and read the
    rest in context.
    """

    ENTROPY_MASK_THRESHOLD = 3.5
    """Bits per character above which a run is treated as random.

    English prose sits near 4 bits per character over its own alphabet; source
    identifiers and paths sit lower over this one. Random credential material is
    close to the theoretical maximum. The threshold is set low enough to catch
    real secrets and accepts that some long identifiers are masked with them.
    """

    _HIGH_ENTROPY_RUN = re.compile(r"[A-Za-z0-9+/_\-=~!@$]{16,}")
    """Long runs of credential-alphabet characters.

    Deliberately broad. It covers base64, hex, JWT segments, and most API-key
    formats in one pattern. Over-masking costs a reader some context they can
    recover by opening the file; under-masking is unrecoverable once the value
    is in a log.

    Sixteen characters, not twenty, and the alphabet includes `~!@$`. The
    tighter form split a secret containing punctuation into fragments below the
    threshold and let them through unmasked, and a nineteen-character token
    passed whole.

    `.` is deliberately excluded. Including it merges dotted identifiers into
    one run -- `process.env.PORT` is sixteen characters and entirely ordinary --
    and masking those makes the output unreadable. A dotted secret splits into
    fragments here, and the credential-shape pass above catches the formats
    where that matters, JWTs included.
    """

    _ASSIGNMENT = re.compile(
        r"""(?ix)
        \b(
            pass(?:wo?rd)? | secret | token | api[_-]?key | auth(?:orization)? |
            credential | private[_-]?key | access[_-]?key | bearer
        )
        \s* [:=]? \s*
        (['"]?)([^\s'"]{4,})\2
        """
    )
    """A credential-shaped name assigned a value.

    The name is what makes this reliable. Entropy alone cannot distinguish a
    password from a hash, but a value assigned to something called `password` is
    a password regardless of how it scores.
    """

    _CREDENTIAL_SHAPE = re.compile(
        r"""(?x)
        AKIA[0-9A-Z]{16}
      | ghp_[A-Za-z0-9]{36}
      | gho_[A-Za-z0-9]{36}
      | ghu_[A-Za-z0-9]{36}
      | ghs_[A-Za-z0-9]{36}
      | ghr_[A-Za-z0-9]{36}
      | github_pat_[A-Za-z0-9_]{22,}
      | sk_live_[A-Za-z0-9]{16,}
      | rk_live_[A-Za-z0-9]{16,}
      | npm_[A-Za-z0-9]{36}
      | xox[baprs]-[A-Za-z0-9-]{10,}
      | AIza[0-9A-Za-z_\-]{35}
      | eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}
      | -----BEGIN[ A-Z]*PRIVATE KEY-----
        """
    )
    """Issuer-defined credential formats.

    Matched before anything entropy-based, because these are exact. A token is
    recognisable by its prefix whatever its body scores, and a real token with a
    padded or repeated body sits below any sensible entropy floor while still
    being live.
    """

    _MODE_ORDER: ClassVar[dict[RedactionMode, int]] = {
        RedactionMode.NONE: 0,
        RedactionMode.MASKED: 1,
        RedactionMode.HASH_ONLY: 2,
    }

    @classmethod
    def shannon_entropy(cls, data: str) -> float:
        """Bits of entropy per character."""
        if not data:
            return 0.0
        counts: dict[str, int] = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @classmethod
    def redact(cls, text: str, mode: RedactionMode) -> str | None:
        """Apply a redaction mode to a snippet.

        ``HASH_ONLY`` returns ``None`` rather than a placeholder string, so a
        reporter that forgets to check cannot accidentally render something that
        looks like content.
        """
        if mode is RedactionMode.HASH_ONLY:
            return None

        truncated = text[: cls.MAX_SNIPPET_BYTES]
        if len(text) > cls.MAX_SNIPPET_BYTES:
            truncated += "..."

        if mode is RedactionMode.NONE:
            return truncated

        return cls.mask(truncated)

    @classmethod
    def mask(cls, text: str) -> str:
        """Mask credential-shaped content while preserving structure.

        Three passes, in order of confidence:

        1. Recognisable credential shapes. Exact, and independent of entropy,
           which matters because a real token with a padded or repeated body
           sits below any sensible entropy floor while still being live.
        2. Assignments to credential-named variables. The name survives, the
           value does not, so the finding stays actionable.
        3. Long runs over the credential alphabet whose entropy is high enough
           to be random rather than an identifier.

        Anything left is kept, because masking further would leave nothing a
        reader could act on.
        """
        result = cls._CREDENTIAL_SHAPE.sub(lambda m: f"{m.group(0)[:4]}{cls.MASK}", text)
        result = cls._ASSIGNMENT.sub(lambda m: f"{m.group(1)}{cls._separator(m)}{cls.MASK}", result)
        return cls._HIGH_ENTROPY_RUN.sub(cls._mask_run, result)

    @classmethod
    def _mask_run(cls, match: re.Match[str]) -> str:
        """Mask a high-entropy run completely.

        No prefix is kept. The credential-shape pass above keeps four
        characters, and there that is harmless and useful: the prefix is a
        published issuer marker -- `ghp_`, `AKIA` -- that identifies the kind of
        token without disclosing any of the secret part.

        This pass has no such guarantee. It fires on an arbitrary run, so the
        first four characters are four characters of the secret, published
        alongside a hash of the whole value.
        """
        run = match.group(0)
        if cls.shannon_entropy(run) >= cls.ENTROPY_MASK_THRESHOLD:
            return cls.MASK
        return run

    @staticmethod
    def _separator(match: re.Match[str]) -> str:
        """Recover the assignment operator and spacing from the matched text."""
        whole = match.group(0)
        name_end = len(match.group(1))
        value_start = whole.rindex(match.group(3))
        return whole[name_end:value_start].rstrip("'\"")

    @classmethod
    def build_evidence(
        cls,
        content: FileContent,
        start: int,
        end: int,
        mode: RedactionMode,
        *,
        kind: EvidenceKind = EvidenceKind.SNIPPET,
    ) -> Evidence:
        """Construct redacted evidence for a byte range.

        Redaction happens here, at construction, rather than at render time.
        That ordering is deliberate: no reporter can accidentally emit
        unredacted content if unredacted content never reaches one.

        The hash is always taken over the **raw** matched bytes, before any
        masking, so it identifies the actual artefact rather than its redacted
        rendering. Two scans that mask differently still produce the same hash
        for the same match.
        """
        raw = content.slice(start, end)
        match_hash = Evidence.hash_bytes(raw)

        snippet: str | None = None
        if mode is not RedactionMode.HASH_ONLY:
            line = content.line_of(start)
            snippet = cls.redact(content.line_text(line).strip(), mode)

        return Evidence(
            kind=kind if snippet is not None else EvidenceKind.HASH,
            match_hash=match_hash,
            redaction=mode,
            snippet=snippet,
            span=(start, end),
        )

    @classmethod
    def effective_mode(
        cls, rule_policy: RedactionMode, config_mode: RedactionMode
    ) -> RedactionMode:
        """Resolve the redaction mode for one finding.

        The stricter of the two always wins, and a rule declaring ``HASH_ONLY``
        cannot be relaxed by configuration. Secret rules use that to guarantee
        their matches never appear in output regardless of what a user passes on
        the command line -- because ``--evidence full`` is typed by someone
        debugging a false positive, not by someone who has thought about where
        the log ends up.
        """
        return max(rule_policy, config_mode, key=lambda m: cls._MODE_ORDER[m])


__all__ = ["Redactor"]
