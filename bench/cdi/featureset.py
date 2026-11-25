"""B (Evidence & Feature Extraction): build a FeatureSet from an existing scan row.

Reuse, not a new analyser (CDI §2.1). Findings come straight from the scan JSON; intel vs content is
``VerdictFeatures.is_intel``; package facts are ``VerdictFeatures.package``'s dict; the slot is read
from the finding's path. The ``featureset_digest`` is a NORMALISED-CONTENT key -- it hashes only the
content-source features (name, value, slot), never intel findings or component versions -- so two
scans of the same content share a key across scanner versions. That is the key the gate's lineage
check must use (train-content ∩ eval-content == 0), the leakage that bit us twice.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, ClassVar

from cordon_scanner.decide.verdict import VerdictFeatures

from . import schemas

EXTRACTOR = "cdi.featureset"
EXTRACTOR_VERSION = "1.1.0"
_VERDICT_EXTRACTOR = "decide.verdict.VerdictFeatures"

#: A finding path suffix → the slot it sits in. Mirrors VerdictFeatures._PLACES so the two agree.
_AGENT_TEXT = ("skill.md", "agents.md", "claude.md", "gemini.md", ".mdc")
_PACKAGING = ("package.json", "setup.py", "pyproject.toml", ".gemspec", "cargo.toml", "cargo.lock")
_OPAQUE = (".so", ".dll", ".dylib", ".node", ".wasm", ".pyc", ".exe", ".class", ".jar", ".min.js")

SLOTS = ("install", "build", "import", "when_called", "opaque", "packaging", "agent_text", "none")
"""Where a feature sits, in the row's words: `install` (an install hook or entry), `build` (a CI hook), `import` (what importing the package loads), `when_called` (what an agent runs when it calls the tool or skill), `opaque` (a file that is compiled or minified), `packaging`, `agent_text` and `none`."""

PLACE_SLOT = {
    "install_hook": "install",
    "install_entry": "install",
    "ci_hook": "build",
    "agent_tool": "when_called",
    "skill_named": "when_called",
    "import_entry": "import",
    "library_entry": "import",
    "library_closure": "import",
    "startup_closure": "import",
}
"""The scan's places (`ScanContext.PLACES`) by the slot they are; a file in two places takes the first slot in `SLOTS` order."""


class FeatureFamilies:
    """The feature families the shared representation lists (SI-B1), each with the rule-id prefixes whose findings are its features, or a
    recorded gap saying why it has none yet. A family with neither is a hole the schema test refuses."""

    #: family -> (rule-id prefixes, gap reason). A prefix is matched whole: `SUSPECT.INSTALL` covers `SUSPECT.INSTALL.001`, not `SUSPECT.INSTALLER.001`.
    FAMILIES: ClassVar[dict[str, tuple[tuple[str, ...], str]]] = {
        "metadata": (("SUSPECT.PACKAGE", "SUSPECT.RELEASE", "SUSPECT.TYPOSQUAT"), ""),
        "hooks": (("SUSPECT.INSTALL", "MALWARE.INSTALL", "SUSPECT.CI"), ""),
        "entry_points": ((), "carried by the slot of every feature (install, build, import, when_called), not by a rule"),
        "call_graphs": ((), "GAP: the scan row holds findings, not a call graph; the flow rules report as sources_sinks"),
        "sources_sinks": (("MALWARE.EXFIL", "SUSPECT.EXFIL"), ""),
        "dynamic_loading": (("SUSPECT.DECODE_EXEC",), ""),
        "obfuscation": (("SUSPECT.OBFUSCATION",), ""),
        "download_execute": (("SUSPECT.DROPPER", "MALWARE.DROPPER"), ""),
        "persistence": (("SUSPECT.PERSIST",), ""),
        "crypto_serialisation": ((), "GAP: no rule or feature reads cryptography or serialisation in its context yet"),
        "similarity": (("MALWARE.CODE.REUSE",), ""),
        "provenance_inconsistencies": (("SUSPECT.PROVENANCE", "SUSPECT.SOURCE"), ""),
        "agent_mcp_permissions": (("SUSPECT.AGENT", "SUSPECT.MCP", "MALWARE.AGENT"), ""),
        "language_binary": (("SUSPECT.BINARY", "SUSPECT.POLYGLOT"), ""),
    }  # fmt: skip
    SLOT_FAMILY: ClassVar[frozenset[str]] = frozenset({"install", "build", "import", "when_called"})

    @classmethod
    def of(cls, feature: Mapping[str, Any]) -> set[str]:
        """The families a feature belongs to: by its rule id (a finding), by the package fact it is, and `entry_points` when it sits in a place the package runs from."""
        found: set[str] = set()
        name = str(feature.get("name", ""))
        if name.startswith("finding:"):
            rule = name.removeprefix("finding:")
            for family, (prefixes, _) in cls.FAMILIES.items():
                if any(rule.startswith(prefix + ".") for prefix in prefixes):
                    found.add(family)
        elif name.startswith("pkg:"):
            found.add("hooks" if name == "pkg:hook" else "metadata")
        if feature.get("slot") in cls.SLOT_FAMILY:
            found.add("entry_points")
        return found

    @classmethod
    def gaps(cls) -> dict[str, str]:
        """The families with no rule behind them, each with its recorded reason."""
        return {
            family: why
            for family, (prefixes, why) in cls.FAMILIES.items()
            if not prefixes and why.startswith("GAP")
        }


class AiFeatures:
    """A feature an AI component produced (SI-B2). Besides the fields every feature has (location, confidence, evidence, extractor and its
    version) it records the model's identity: the model version, the prompt template, the inputs it read (digests, never their text), and the
    output schema it was held to. The five are required; a record missing one is refused. An AI feature is `source: ai`: it is never part of
    the content digest, so a new model version does not move the key the lineage check compares."""

    REQUIRED: ClassVar[tuple[str, ...]] = (
        "model_version",
        "template",
        "inputs",
        "schema",
        "confidence",
    )

    @classmethod
    def record(
        cls,
        name: str,
        value: Any,
        *,
        model_version: str,
        template: str,
        inputs: Iterable[str],
        schema: str,
        confidence: float,
        evidence: str = "",
        location: Mapping[str, Any] | None = None,
        slot: str = "none",
    ) -> dict[str, Any]:
        """The feature record, or `ValueError` for a field that is empty, an input that is not a sha256 digest, or a confidence outside 0 to 1."""
        listed = list(inputs)
        for field, given in (
            ("model_version", model_version),
            ("template", template),
            ("schema", schema),
        ):
            if not isinstance(given, str) or not given:
                raise ValueError(f"an AI feature records its {field}")
        if not listed or not all(isinstance(i, str) and i.startswith("sha256:") for i in listed):
            raise ValueError("an AI feature records the digests of the inputs it read")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
        ):
            raise ValueError("an AI feature records its confidence, 0 to 1")
        if slot not in SLOTS:
            raise ValueError(f"a slot is one of {', '.join(SLOTS)}")
        return {
            "name": f"ai:{name}",
            "value": value,
            "source": "ai",
            "slot": slot,
            "location": dict(location) if location else {"path": None, "line": None},
            "confidence": float(confidence),
            "evidence": evidence or model_version,
            "extractor": f"ai:{model_version}",
            "extractor_version": EXTRACTOR_VERSION,
            "ai": {
                "model_version": model_version,
                "template": template,
                "inputs": listed,
                "schema": schema,
            },
        }

    @classmethod
    def complete(cls, feature: Mapping[str, Any]) -> bool:
        """Whether a feature record carries the five fields (the four in `ai`, and the confidence beside them)."""
        ai = feature.get("ai")
        return (
            isinstance(ai, dict)
            and all(ai.get(f) for f in ("model_version", "template", "inputs", "schema"))
            and isinstance(feature.get("confidence"), (int, float))
        )


class FeatureSetBuilder:
    """Build a FeatureSet from a scan row. Stateless; call the static methods."""

    @staticmethod
    def _placed(places: Mapping[str, Iterable[str]] | None) -> dict[str, str]:
        """Each file path of the row's `places` (place -> paths) with the slot of the place it runs from."""
        placed: dict[str, str] = {}
        for place in sorted(places or {}, key=lambda p: SLOTS.index(PLACE_SLOT.get(p, "none"))):
            slot = PLACE_SLOT.get(place)
            for path in (places or {})[place]:
                if slot is not None:
                    placed.setdefault(str(path).lower().rsplit("!", 1)[-1], slot)
        return placed

    @staticmethod
    def _slot(path: str | None, placed: Mapping[str, str] | None = None) -> str:
        p = (path or "").lower().rsplit("!", 1)[-1]
        if not p:
            return "none"
        base = p.rsplit("/", 1)[-1]
        if (
            base == "skill.md"
            or base in {"agents.md", "claude.md", "gemini.md"}
            or p.endswith(".mdc")
        ):
            return "agent_text"
        if p.endswith(_PACKAGING):
            return "packaging"
        if p.endswith(_OPAQUE):
            return "opaque"
        return (placed or {}).get(p, "none")

    @staticmethod
    def _finding_feature(
        finding: list[Any], placed: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        # A scan finding is the 7-tuple [rule, severity, confidence, category, path, line, detector].
        rule, severity, confidence, category, path, line, detector = (list(finding) + [None] * 7)[
            :7
        ]
        return {
            "name": f"finding:{rule}",
            "value": True,
            "source": "intel" if VerdictFeatures.is_intel(str(rule)) else "content",
            "slot": FeatureSetBuilder._slot(path, placed),
            "location": {"path": path, "line": line},
            "confidence": confidence,
            "evidence": rule,
            "category": category,
            "severity": severity,
            "extractor": detector or EXTRACTOR,
            "extractor_version": EXTRACTOR_VERSION,
        }

    @staticmethod
    def _package_feature(name: str, value: Any) -> dict[str, Any]:
        return {
            "name": f"pkg:{name}",
            "value": value,
            "source": "content",  # VerdictFeatures.package reads only the package's own files
            "slot": "packaging"
            if name in {"hook", "n_deps", "version_odd", "name_digits"}
            else "none",
            "location": {"path": None, "line": None},
            "confidence": 1.0,
            "evidence": _VERDICT_EXTRACTOR,
            "cosmetic": name in VerdictFeatures.COSMETIC,
            "extractor": _VERDICT_EXTRACTOR,
            "extractor_version": EXTRACTOR_VERSION,
        }

    @staticmethod
    def _content_key(features: list[dict[str, Any]]) -> str:
        """The normalised-content digest: content features only, stripped of location/confidence/
        versions, sorted. Identical content → identical key, across scanner versions and intel."""
        core = sorted(
            (f["name"], f["value"], f["slot"]) for f in features if f.get("source") == "content"
        )
        return schemas.Schemas.digest(core)

    @staticmethod
    def build_featureset(
        scan_row: dict[str, Any],
        *,
        artifact_id: str,
        ecosystem: str,
        versions: dict[str, str] | None = None,
        package_features: dict[str, Any] | None = None,
        ai_features: Iterable[dict[str, Any]] = (),
    ) -> dict[str, Any]:
        """Deterministic: the same scan row + ids give the same FeatureSet, digest included. `ai_features` are `AiFeatures.record`s; one that
        does not carry its five fields is refused (`ValueError`)."""
        versions = versions or {}
        verdict = scan_row.get("verdict") if isinstance(scan_row.get("verdict"), dict) else {}
        pkg = package_features if package_features is not None else (verdict.get("package") or {})

        placed = FeatureSetBuilder._placed(scan_row.get("places"))
        features: list[dict[str, Any]] = [
            FeatureSetBuilder._finding_feature(f, placed) for f in (scan_row.get("findings") or [])
        ]
        features += [FeatureSetBuilder._package_feature(k, v) for k, v in sorted(pkg.items())]
        for ai in ai_features:
            if not AiFeatures.complete(ai):
                raise ValueError(
                    "an AI feature carries its model version, template, inputs, schema and confidence"
                )
            features.append(ai)

        record = {
            "schema_version": schemas.SCHEMA_VERSIONS["FeatureSet"],
            "featureset_digest": FeatureSetBuilder._content_key(features),
            "artifact_id": artifact_id,
            "artifact_digest": scan_row.get("sha256") or scan_row.get("file") or artifact_id,
            "ecosystem": ecosystem,
            "scanner_version": versions.get("scanner"),
            "intel_version": versions.get("intel"),
            "model_version": versions.get("model"),
            "extractors": {EXTRACTOR: EXTRACTOR_VERSION, _VERDICT_EXTRACTOR: EXTRACTOR_VERSION},
            "features": features,
            "verdict_features": dict(pkg),
        }
        return schemas.Schemas.validate("FeatureSet", record)
