"""One file naming the credential stores of several unrelated services.

A cloud SDK reads `~/.aws/credentials`; a stealer reads that, the SSH keys, `.npmrc`, `.netrc`,
the kube and Docker configs and the GitHub CLI's tokens, because it takes whatever is there
(review 98: the 2025 Go `BufferZoneCorp/*` family, its paths XOR-encoded and recovered by
`detect/go_eval.py`). Read from the file as resolved, in any language; documentation is excluded
by the rule's path filter.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from cordon_scanner.detect.code.capability.hits import CapabilityHit
    from cordon_scanner.foundation.content import FileContent


class CredentialSweep:
    """`CAP.CREDENTIAL.SWEEP`: the stores of at least `SWEEP_MIN` services in one file."""

    #: Where one service keeps its credentials on disk, by service. A tool reads its own; a
    #: stealer reads every one it knows.
    STORES: ClassVar[dict[str, re.Pattern[str]]] = {
        name: re.compile(pattern)
        for name, pattern in {
            "ssh": r"\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|identity)\b",
            "aws": r"\.aws/credentials\b",
            "npm": r"(?<![\w.])\.npmrc\b",
            "netrc": r"(?<![\w.])\.netrc\b",
            "kube": r"\.kube/config\b",
            "docker": r"\.docker/config\.json\b",
            "gh": r"\.config/gh/hosts\.ya?ml\b",
            "git": r"(?<![\w.])\.git-credentials\b",
            "pypi": r"(?<![\w.])\.pypirc\b",
            "gcloud": r"\.config/gcloud/(?:credentials\.db|application_default_credentials\.json)",
            "azure": r"\.azure/(?:accessTokens|msal_token_cache)",
        }.items()
    }
    #: The text every match of each store's pattern contains: a store whose text is absent from a
    #: file cannot match there, so a file holding fewer than `SWEEP_MIN` of them is no sweep, found
    #: by a substring test without running a pattern. Most of the patterns open with a lookbehind,
    #: which the regular expression engine cannot skip ahead to, so each tested every character
    #: of every file: 1.2 s of alembic's warm scan (measured 2026-10-31).
    LITERALS: ClassVar[dict[str, str]] = {
        "ssh": ".ssh/",
        "aws": ".aws/credentials",
        "npm": ".npmrc",
        "netrc": ".netrc",
        "kube": ".kube/config",
        "docker": ".docker/config.json",
        "gh": ".config/gh/hosts.y",
        "git": ".git-credentials",
        "pypi": ".pypirc",
        "gcloud": ".config/gcloud/",
        "azure": ".azure/",
    }
    #: Distinct services' stores before reading them is a sweep rather than a tool's own login.
    SWEEP_MIN: ClassVar[int] = 3

    @classmethod
    def hits(cls, content: FileContent) -> list[CapabilityHit]:
        from cordon_scanner.detect.code.capability.hits import CapabilityHit

        text = content.text
        if len(text) > 4_000_000:
            return []
        present = [name for name, literal in cls.LITERALS.items() if literal in text]
        if len(present) < cls.SWEEP_MIN:
            return []
        found: list[tuple[int, str]] = []
        for name in present:
            match = cls.STORES[name].search(text)
            if match:
                found.append((match.start(), name))
        if len({name for _, name in found}) < cls.SWEEP_MIN:
            return []
        first = min(offset for offset, _ in found)
        start = len(text[:first].encode("utf-8"))
        return [
            CapabilityHit(
                capability=Capability.CREDENTIAL,
                rule_id="CAP.CREDENTIAL.SWEEP",
                byte_start=start,
                byte_end=start + 1,
                line=text.count("\n", 0, first) + 1,
            )
        ]


__all__ = ["CredentialSweep"]
