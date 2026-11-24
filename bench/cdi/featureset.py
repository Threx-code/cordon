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
from typing import Any

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
    ) -> dict[str, Any]:
        """Deterministic: the same scan row + ids give the same FeatureSet, digest included."""
        versions = versions or {}
        verdict = scan_row.get("verdict") if isinstance(scan_row.get("verdict"), dict) else {}
        pkg = package_features if package_features is not None else (verdict.get("package") or {})

        placed = FeatureSetBuilder._placed(scan_row.get("places"))
        features: list[dict[str, Any]] = [
            FeatureSetBuilder._finding_feature(f, placed) for f in (scan_row.get("findings") or [])
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
