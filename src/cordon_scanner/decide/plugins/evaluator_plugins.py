"""Third-party trust evaluators, taken only as signed, versioned data and recorded as evidence.

An evaluator plugin is a manifest (its id, its version, a table of conditions over the facts of an artifact and the
verdict each gives) and a signature over the manifest's canonical form by a key the installation pins. The table is
read by this module and nothing in it is run: a plugin cannot reach the file system, the network or the process, because
it holds no code. A bundle that is unsigned, signed by a key that is not pinned, altered after signing, of a version
that is not `major.minor.patch`, of another kind, or larger than the bounds is refused with the reason. A verdict
enters the decision as a finding of category `policy`, named by the plugin and its version.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from cordon_scanner.decide.decision.evidence import FindingFact
from cordon_scanner.rules.pack_signatures import PackSignatures

MAX_RULES: Final = 200
MAX_BYTES: Final = 65_536


class PluginRefused(Exception):
    """A plugin bundle that is not taken; the message says which clause failed."""


@dataclass(frozen=True, slots=True)
class PluginVerdict:
    """What an evaluator says of one artifact: a severity and a one-line reason, or nothing."""

    rule: str
    severity: str
    reason: str


@dataclass(frozen=True, slots=True)
class EvaluatorPlugin:
    """A plugin that was verified: its identity and its table of conditions."""

    plugin_id: str
    version: str
    table: tuple[dict[str, Any], ...]

    SEVERITIES: ClassVar[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

    @property
    def name(self) -> str:
        return f"PLUGIN.{self.plugin_id}.{self.version}"

    def evaluate(self, facts: Mapping[str, str]) -> PluginVerdict | None:
        """The verdict of the first entry whose every condition equals the fact of the same name, else None."""
        for entry in self.table:
            conditions = entry["when"]
            if conditions and all(facts.get(field) == value for field, value in conditions.items()):
                return PluginVerdict(entry["id"], entry["severity"], entry["reason"])
        return None

    def evidence(self, verdict: PluginVerdict, path: str = "") -> FindingFact:
        """The verdict as a finding a policy can match, so it is recorded with the rest of the evidence."""
        return FindingFact(
            rule_id=f"{self.name}.{verdict.rule}",
            severity=verdict.severity,
            confidence="medium",
            category="policy",
            domain="plugin",
            path=path,
            line=None,
        )


class EvaluatorPlugins:
    """Loads signed evaluator plugins."""

    PINNED: ClassVar[tuple[str, ...]] = ()
    """Hex Ed25519 public keys of the integration programme's signers, fixed at the release build."""

    VERSION: ClassVar[re.Pattern[str]] = re.compile(r"\d{1,6}\.\d{1,6}\.\d{1,6}")
    IDENTIFIER: ClassVar[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_-]{1,40}")

    @classmethod
    def load(cls, bundle: Any, pinned: tuple[str, ...] | None = None) -> EvaluatorPlugin:
        """The plugin of a signed bundle, or PluginRefused."""
        keys = cls.PINNED if pinned is None else pinned
        if not isinstance(bundle, dict) or not isinstance(bundle.get("manifest"), dict):
            raise PluginRefused("not a plugin bundle")
        manifest = bundle["manifest"]
        message = PackSignatures.canonical(manifest)
        if len(message) > MAX_BYTES:
            raise PluginRefused("the manifest is larger than the bound")
        if bundle.get("signature") is None:
            raise PluginRefused("unsigned")
        if not PackSignatures.verifies(bundle["signature"], keys, message):
            raise PluginRefused("the signature does not verify under a pinned key")
        return cls._plugin(manifest)

    @classmethod
    def _plugin(cls, manifest: dict[str, Any]) -> EvaluatorPlugin:
        plugin_id, version = manifest.get("id"), manifest.get("version")
        if manifest.get("kind") != "evaluator":
            raise PluginRefused("the kind is not `evaluator`")
        if not isinstance(plugin_id, str) or not cls.IDENTIFIER.fullmatch(plugin_id):
            raise PluginRefused("the id is not a plain name")
        if not isinstance(version, str) or not cls.VERSION.fullmatch(version):
            raise PluginRefused("the version is not major.minor.patch")
        table = manifest.get("table")
        if not isinstance(table, list) or not table or len(table) > MAX_RULES:
            raise PluginRefused("the table is empty or larger than the bound")
        return EvaluatorPlugin(plugin_id, version, tuple(cls._entry(item) for item in table))

    @classmethod
    def _entry(cls, item: Any) -> dict[str, Any]:
        if not isinstance(item, dict) or set(item) != {"id", "when", "severity", "reason"}:
            raise PluginRefused("a table entry has other keys than id, when, severity and reason")
        when = item["when"]
        valid = (
            isinstance(item["id"], str)
            and cls.IDENTIFIER.fullmatch(item["id"])
            and isinstance(item["reason"], str)
            and len(item["reason"]) <= 300
            and item["severity"] in EvaluatorPlugin.SEVERITIES
            and isinstance(when, dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in when.items())
        )
        if not valid:
            raise PluginRefused("a table entry is malformed")
        return item


__all__ = ["EvaluatorPlugin", "EvaluatorPlugins", "PluginRefused", "PluginVerdict"]
