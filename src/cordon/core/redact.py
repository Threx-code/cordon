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
from typing import TYPE_CHECKING

from cordon.core.models import Evidence, EvidenceKind, RedactionMode

if TYPE_CHECKING:
    from cordon.core.content import FileContent

MASK = "[redacted]"

MAX_SNIPPET_BYTES = 200
"""Cap on snippet length.

A long snippet is not more informative; it is more leakage. The reader needs
enough to recognise the construct, and the file and line to go and read the rest
in context.
"""

_HIGH_ENTROPY_RUN = re.compile(r"[A-Za-z0-9+/_\-=]{20,}")
"""Long runs of credential-alphabet characters.

Deliberately broad. It covers base64, hex, JWT segments, and most API-key
formats in one pattern. Over-masking costs a reader some context they can
recover by opening the file; under-masking is unrecoverable once the value is in
a log.
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

Masks the value while keeping the name, so a reader still learns which setting
is at fault. That distinction is the whole point of masking rather than
suppressing: the finding stays actionable.
"""

_CREDENTIAL_SHAPE = re.compile(
    r"""(?x)
    \b(?:
        (?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}
      | (?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}
      | github_pat_[A-Za-z0-9_]{20,}
      | xox[abprs]-[0-9A-Za-z-]{10,}
      | (?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}
      | AIza[0-9A-Za-z_\-]{35}
      | npm_[A-Za-z0-9]{36}
      | pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}
      | eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}
    )
    """
)
"""Credential shapes, masked regardless of entropy.

Entropy gating alone is not sufficient here, and the gap is easy to miss: a
token is recognisable by its *prefix*, and a prefix plus a low-entropy body --
a padded, repeated or sequential value -- sits below any sensible entropy floor
while still being a live credential. Shape and entropy therefore both mask, and
either one is enough.
"""

ENTROPY_MASK_THRESHOLD = 3.5
"""Shannon entropy (bits per character) above which a run is masked.

English prose sits near 4.0 bits per character but over a small alphabet;
identifiers and paths sit lower over this one. Random credential material is
close to the theoretical maximum. The threshold is set low enough to catch real
secrets and accepts that some long identifiers are masked with them.
"""


def shannon_entropy(data: str) -> float:
    """Bits of entropy per character."""
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(text: str, mode: RedactionMode) -> str | None:
    """Apply a redaction mode to a snippet.

    ``HASH_ONLY`` returns ``None`` rather than a placeholder string, so a
    reporter that forgets to check cannot accidentally render something that
    looks like content.
    """
    if mode is RedactionMode.HASH_ONLY:
        return None

    truncated = text[:MAX_SNIPPET_BYTES]
    if len(text) > MAX_SNIPPET_BYTES:
        truncated += "..."

    if mode is RedactionMode.NONE:
        return truncated

    return mask(truncated)


def mask(text: str) -> str:
    """Mask credential-shaped content while preserving structure.

    Three passes, in order of confidence:

    1. Recognisable credential shapes. Exact, and independent of entropy, which
       matters because a real token with a padded or repeated body sits below
       any sensible entropy floor while still being live.
    2. Assignments to credential-named variables. The name survives, the value
       does not, so the finding stays actionable.
    3. Long runs over the credential alphabet whose entropy is high enough to be
       random rather than an identifier.

    Anything left is kept, because masking further would leave nothing a reader
    could act on.
    """
    # Recognisable credential shapes first, since they are exact and do not
    # depend on the value's entropy.
    result = _CREDENTIAL_SHAPE.sub(lambda m: f"{m.group(0)[:4]}{MASK}", text)
    result = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{_separator(m)}{MASK}", result)

    def mask_run(match: re.Match[str]) -> str:
        run = match.group(0)
        if shannon_entropy(run) >= ENTROPY_MASK_THRESHOLD:
            return f"{run[:4]}{MASK}"
        return run

    return _HIGH_ENTROPY_RUN.sub(mask_run, result)


def _separator(match: re.Match[str]) -> str:
    """Recover the assignment operator and spacing from the matched text."""
    whole = match.group(0)
    name_end = len(match.group(1))
    value_start = whole.rindex(match.group(3))
    return whole[name_end:value_start].rstrip("'\"")


def build_evidence(
    content: FileContent,
    start: int,
    end: int,
    mode: RedactionMode,
    *,
    kind: EvidenceKind = EvidenceKind.SNIPPET,
) -> Evidence:
    """Construct redacted evidence for a byte range.

    Redaction happens here, at construction, rather than at render time. That
    ordering is deliberate: no reporter can accidentally emit unredacted content
    if unredacted content never reaches one.

    The hash is always taken over the **raw** matched bytes, before any masking,
    so it identifies the actual artefact rather than its redacted rendering. Two
    scans that mask differently still produce the same hash for the same match.
    """
    raw = content.slice(start, end)
    match_hash = Evidence.hash_bytes(raw)

    snippet: str | None = None
    if mode is not RedactionMode.HASH_ONLY:
        line = content.line_of(start)
        snippet = redact(content.line_text(line).strip(), mode)

    return Evidence(
        kind=kind if snippet is not None else EvidenceKind.HASH,
        match_hash=match_hash,
        redaction=mode,
        snippet=snippet,
        span=(start, end),
    )


def effective_mode(rule_policy: RedactionMode, config_mode: RedactionMode) -> RedactionMode:
    """Resolve the redaction mode for one finding.

    The stricter of the two always wins, and a rule declaring ``HASH_ONLY``
    cannot be relaxed by configuration. Secret rules use that to guarantee their
    matches never appear in output regardless of what a user passes on the
    command line -- because ``--evidence full`` is typed by someone debugging a
    false positive, not by someone who has thought about where the log ends up.
    """
    order = {RedactionMode.NONE: 0, RedactionMode.MASKED: 1, RedactionMode.HASH_ONLY: 2}
    return max(rule_policy, config_mode, key=lambda m: order[m])


__all__ = [
    "ENTROPY_MASK_THRESHOLD",
    "MASK",
    "MAX_SNIPPET_BYTES",
    "build_evidence",
    "effective_mode",
    "mask",
    "redact",
    "shannon_entropy",
]
