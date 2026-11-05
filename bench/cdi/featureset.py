"""B (Evidence & Feature Extraction): build a FeatureSet from an existing scan row.

Reuse, not a new analyser (CDI §2.1). Findings come straight from the scan JSON; intel vs content is
``VerdictFeatures.is_intel``; package facts are ``VerdictFeatures.package``'s dict; the slot is read
from the finding's path. The ``featureset_digest`` is a NORMALISED-CONTENT key -- it hashes only the
content-source features (name, value, slot), never intel findings or component versions -- so two
scans of the same content share a key across scanner versions. That is the key the gate's lineage
check must use (train-content ∩ eval-content == 0), the leakage that bit us twice.
"""

from __future__ import annotations

from typing import Any

from cordon_scanner.decide.verdict import VerdictFeatures

from . import schemas

EXTRACTOR = "cdi.featureset"
EXTRACTOR_VERSION = "1.0.0"
_VERDICT_EXTRACTOR = "decide.verdict.VerdictFeatures"

#: A finding path suffix → the slot it sits in. Mirrors VerdictFeatures._PLACES so the two agree.
_AGENT_TEXT = ("skill.md", "agents.md", "claude.md", "gemini.md", ".mdc")
_PROSE = (".md", ".mdc", ".txt", ".rst")
_PACKAGING = ("package.json", "setup.py", "pyproject.toml", ".gemspec", "cargo.toml", "cargo.lock")


class FeatureSetBuilder:
    """Build a FeatureSet from a scan row. Stateless; call the static methods."""

    @staticmethod
    def _slot(path: str | None) -> str:
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
        if p.endswith(_PROSE):
            return "text"
        return "code"

    @staticmethod
    def _finding_feature(finding: list[Any]) -> dict[str, Any]:
        # A scan finding is the 7-tuple [rule, severity, confidence, category, path, line, detector].
        rule, severity, confidence, category, path, line, detector = (list(finding) + [None] * 7)[
            :7
        ]
        return {
            "name": f"finding:{rule}",
            "value": True,
            "source": "intel" if VerdictFeatures.is_intel(str(rule)) else "content",
            "slot": FeatureSetBuilder._slot(path),
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
    ) -> dict[str, Any]:
        """Deterministic: the same scan row + ids give the same FeatureSet, digest included."""
        versions = versions or {}
        verdict = scan_row.get("verdict") if isinstance(scan_row.get("verdict"), dict) else {}
        pkg = package_features if package_features is not None else (verdict.get("package") or {})

        features: list[dict[str, Any]] = [
            FeatureSetBuilder._finding_feature(f) for f in (scan_row.get("findings") or [])
        ]
        features += [FeatureSetBuilder._package_feature(k, v) for k, v in sorted(pkg.items())]

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
