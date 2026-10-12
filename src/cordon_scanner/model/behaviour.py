"""What a package's code does, as Cordon's own analysis labels it: features for Cordon's model.

The words a package uses are the same in malware and in ordinary code -- `http`, `exec`, `env`. What
tells them apart is behaviour, and above all behaviours that occur together: secrets read and sent,
a download run, a payload decoded and executed, at install time. A large study of npm detectors
found exactly that coupling to be the deciding signal (arXiv:2603.27549).

The labels are the scanner's own capability labels, from the same rule packs and the same engine a
scan uses (`CapabilityDetector.labels`), so the features computed on a user's machine are the ones
the model was trained on. Per capability: how many code files carry it, and whether a file an
install hook or an entry point runs does. Per coupled pair: how many files carry both, and whether a
hook or entry file does.
"""

from __future__ import annotations

import functools
import math
from typing import TYPE_CHECKING, Final

from cordon_scanner.core.content import FileContent
from cordon_scanner.langs.registry import LanguageRegistry

if TYPE_CHECKING:
    from cordon_scanner.rules.loader import RuleSet

CAPABILITIES: Final = (
    "decode", "execute", "decompress", "deserialize", "spawn", "credential", "reconnaissance",
    "egress", "persist", "dynamic_dispatch", "fetch_exec", "anti_analysis", "delay", "wallet",
    "targeting", "destroy", "mine",
)  # fmt: skip
"""In a fixed order: the feature layout, which a model bundle records and the server checks."""

COUPLED: Final = (
    ("credential", "egress"), ("decode", "execute"), ("decode", "spawn"), ("decode", "egress"),
    ("egress", "spawn"), ("egress", "execute"), ("egress", "persist"), ("reconnaissance", "egress"),
    ("credential", "spawn"), ("wallet", "egress"), ("anti_analysis", "egress"),
    ("anti_analysis", "spawn"), ("deserialize", "egress"), ("destroy", "targeting"),
)  # fmt: skip
"""Behaviours that mean something together: collection then exfiltration, a fetch then a run."""

BEHAVIOUR_DENSE: Final[tuple[str, ...]] = (
    "beh_labelled_files",
    *(f"beh_{c}_files" for c in CAPABILITIES),
    *(f"beh_{c}_hook" for c in CAPABILITIES),
    *(f"beh_{a}_{b}_files" for a, b in COUPLED),
    *(f"beh_{a}_{b}_hook" for a, b in COUPLED),
)
MAX_LABELLED: Final = 2000
"""Code files labelled per package: hook and entry files first, then the rest in path order."""


class BehaviourFeatures:
    @staticmethod
    @functools.cache
    def _engine() -> tuple[object, RuleSet]:
        from cordon_scanner.detect.capability import CapabilityDetector
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        return CapabilityDetector(), RuleSet(RuleLoader.load_builtin())

    @staticmethod
    def labels(name: str, body: bytes) -> frozenset[str]:
        """The capabilities one file carries."""
        detector, rules = BehaviourFeatures._engine()
        content = FileContent(path=name, raw=body, size=len(body))
        shebang = (
            body[:200].split(b"\n", 1)[0].decode("utf-8", "replace") if body[:2] == b"#!" else None
        )
        language = LanguageRegistry.identify(name, shebang=shebang)
        return frozenset(hit.capability.value for hit in detector.labels(content, language, rules))  # type: ignore[attr-defined]

    @staticmethod
    def of(code: list[tuple[str, bytes]], runs: set[str]) -> list[float]:
        """Features for a package's code files (rooted paths), `runs` naming the files its install
        hooks and entry points start, by path or path tail."""

        def started(name: str) -> bool:
            return name in runs or any(name.endswith(target) for target in runs if target)

        ordered = sorted(code, key=lambda item: (not started(item[0]), item[0]))[:MAX_LABELLED]
        files: dict[str, int] = dict.fromkeys(CAPABILITIES, 0)
        hook: dict[str, int] = dict.fromkeys(CAPABILITIES, 0)
        pair_files: dict[tuple[str, str], int] = dict.fromkeys(COUPLED, 0)
        pair_hook: dict[tuple[str, str], int] = dict.fromkeys(COUPLED, 0)
        labelled = 0
        for name, body in ordered:
            found = BehaviourFeatures.labels(name, body)
            if not found:
                continue
            labelled += 1
            is_started = started(name)
            for capability in found & files.keys():
                files[capability] += 1
                if is_started:
                    hook[capability] = 1
            for pair in COUPLED:
                if pair[0] in found and pair[1] in found:
                    pair_files[pair] += 1
                    if is_started:
                        pair_hook[pair] = 1
        return [
            math.log1p(labelled),
            *(math.log1p(files[c]) for c in CAPABILITIES),
            *(float(hook[c]) for c in CAPABILITIES),
            *(math.log1p(pair_files[p]) for p in COUPLED),
            *(float(pair_hook[p]) for p in COUPLED),
        ]
