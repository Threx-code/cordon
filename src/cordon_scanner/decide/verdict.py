"""One decision for a scanned package: block or hold -- learned, with a floor it cannot move.

Each rule reports what it sees in one file. Whether a package should fail a build is a different
question, and answering it rule by rule meant any one of 1,400 rules could block alone: measured on
the 234,509-unit benign corpus, single findings blocked 1-7% of most ecosystems while a lot of real
malware also showed only one (review 98). What separates the two is the combination -- which rules,
how strong, where they fired, in what kind of package -- and that is learned on one half of the
data and measured on the other.

```
  findings ──► per rule / family / place / category: strongest severity and count ┐
  package  ──► size, files, hook, dependencies, what it claims and can do          ├─► trees
              (not the cosmetic facts an attacker adds for free: README, licence,  ┘     │
               tests, changelog, repository, description)                     p(malicious)
       │                                                                                 │
       ▼                                                                                 ▼
  floor: known-malware intel, and MALWARE.* rules that never fired on a benign unit,
         are never re-graded
  p >= block of its area (skill, MCP server, npm, PyPI, Open VSX, any other package)
         -> what trips the gate still blocks, and the verdict itself blocks
  p <  block -> every other code finding is held at MEDIUM, suspicious (a warning)
```

The trees are monotone in every finding: a stronger or an extra finding never lowers the score.
Each area's line is set so its own benign units are blocked at most at the shipped share, counted
against every unit of that ecosystem in the corpus (`bench/model/verdict_train.py`).

Without the model file nothing is re-graded; the features are still computed and reported, which is
how the training data is made by the same code that scores it.
"""

from __future__ import annotations

import array
import functools
import gzip
import json
import math
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.decide.feature_schema import FeatureFold, FeatureRecord, FeatureSchema
from cordon_scanner.decide.verdict_features import VerdictFeatures
from cordon_scanner.foundation.models import Category, Confidence, Finding, Severity
from cordon_scanner.foundation.paths import PackagePaths

if TYPE_CHECKING:
    from collections.abc import Sequence

MODEL_PATH: Final = PackagePaths.data("detect") / "verdict.json.gz"

_CODE_SUFFIXES: Final = (
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".py",
    ".rb",
    ".php",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".sh",
    ".ps1",
    ".lua",
    ".pl",
)
_INFRA: Final = ("SUSPECT.IAC.", "SUSPECT.K8S.", "SUSPECT.CFN.")


class VerdictModel:
    """Gradient-boosted trees shipped as data, evaluated here without a dependency.

    `detect/data/verdict.json.gz` (`bench/model/verdict_train.py`): the feature names in order, the
    trees, trees of its own for an area that needs them (`by_area`), a line per area, the floor,
    and a manifest of what it was trained and measured on.

    Format 3 is fitted on folded features (`FeatureFold`) and records the fold it was fitted at
    (`FeatureFold.stamp()`): it is loaded only at this tree's fold, and scored on folded features.
    Format 2, from before the fold, was fitted on the raw features and is scored on them.
    """

    FORMAT: ClassVar[int] = 3
    UNFOLDED: ClassVar[int] = 2

    @staticmethod
    @functools.cache
    def load(path: Path = MODEL_PATH) -> dict[str, Any] | None:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                model: dict[str, Any] = json.load(handle)
        except OSError:
            return None
        if model.get("format") == VerdictModel.UNFOLDED:
            return model
        if (
            model.get("format") == VerdictModel.FORMAT
            and model.get("fold") == FeatureFold.version()
        ):
            return model
        return None

    @staticmethod
    def inputs(model: dict[str, Any], features: dict[str, float]) -> dict[str, float]:
        """The features `model` and its sections (`by_area`, `registry`) are scored on: folded for a
        model fitted on folded features, raw for one fitted before the fold."""
        return (
            features
            if model.get("format") == VerdictModel.UNFOLDED
            else FeatureFold.apply(features)
        )

    @staticmethod
    def score(model: dict[str, Any], features: dict[str, float]) -> float:
        # In single precision, as the trees were fitted: a value near a split would otherwise fall
        # on the other side of it.
        vector = array.array("f", [features.get(name, 0.0) for name in model["features"]])
        raw = float(model["baseline"])
        for tree in model["trees"]:
            node = 0
            while True:
                n = tree[node]
                if n["leaf"]:
                    raw += n["value"]
                    break
                x = vector[n["feature"]]
                node = (
                    n["left"]
                    if (x <= n["threshold"] if not math.isnan(x) else n["missing_left"])
                    else n["right"]
                )
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, raw))))


class Verdict:
    FLOOR_CONFIDENCE: ClassVar[frozenset[Confidence]] = frozenset(
        {Confidence.HIGH, Confidence.CONFIRMED}
    )
    RULE: ClassVar[str] = VerdictFeatures.OWN_RULE
    #: The line every package without one of its own answers to: the strictest of them all.
    FALLBACK: ClassVar[str] = "package"
    _PYPI: ClassVar[re.Pattern[str]] = re.compile(r"^[^/]+/PKG-INFO$|^[^/]+\.dist-info/METADATA$")
    #: Each ecosystem's layout, read on the outermost archive only (a jar bundled in a Gradle
    #: repository is not a Maven release), measured on the benign corpus (2026-10-19). Release
    #: formats first: a gem's `metadata.gz`, a crate's `Cargo.toml.orig`, a nupkg's `.nuspec`, a
    #: jar's manifest, a Go module zip, a conda package's `info/`, a Hex tarball, an Ansible
    #: collection's `FILES.json`, an image export. Then project layouts, one directory deep at most.
    #: Benign code of each carries different findings by nature, so each answers to its own line.
    _ECOSYSTEMS: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = tuple(
        (name, re.compile(layout))
        for name, layout in (
            ("rubygems", r"^metadata\.gz$"),
            ("crates", r"^[^/]+-\d[^/]*/Cargo\.toml\.orig$"),
            ("nuget", r"^[^/]+\.nuspec$"),
            ("maven", r"^META-INF/(?:MANIFEST\.MF$|maven/)"),
            ("go", r"^(?:[^/]+/)*[^/@]+@v\d[^/]*/"),
            ("conda", r"^info/index\.json$|^info-[^/]+\.tar\.zst$"),
            ("hex", r"^metadata\.config$"),
            ("galaxy", r"^FILES\.json$"),
            ("image", r"^image-config/|^sha256:[0-9a-f]{64}$|^blobs/sha256/"),
            ("packagist", r"^[^/]+/composer\.json$"),
            ("cran", r"^[^/]+/DESCRIPTION$"),
            ("pub", r"^(?:[^/]+/)?pubspec\.yaml$"),
            ("swift", r"^(?:[^/]+/)?Package\.swift$"),
            ("cocoapods", r"^(?:[^/]+/)?[^/]+\.podspec(?:\.json)?$"),
            ("hackage", r"^(?:[^/]+/)?[^/]+\.cabal$"),
            ("helm", r"^(?:[^/]+/)?Chart\.yaml$"),
            ("conan", r"^(?:[^/]+/)?conanfile\.py$"),
            ("vcpkg", r"^(?:[^/]+/)?(?:vcpkg\.json|portfile\.cmake)$"),
            ("opam", r"^(?:[^/]+/)?(?:[^/]+\.opam|opam|dune-project|_oasis|OMakeroot)$"),
            ("julia", r"^(?:[^/]+/)?(?:Julia)?Project\.toml$"),
            ("bazel", r"^(?:[^/]+/)?(?:MODULE\.bazel|WORKSPACE(?:\.bazel)?)$"),
            ("gradle", r"^(?:[^/]+/){0,2}(?:settings|build)\.gradle(?:\.kts)?$"),
            ("nix", r"^(?:[^/]+/)?(?:flake|default)\.nix$"),
            ("homebrew", r"^(?:[^/]+/)?(?:Formula|Casks)/(?:[^/]+/)*[^/]+\.rb$"),
            ("terraform", r"^(?:[^/]+/)?[^/]+\.tf$"),
        )
    )
    #: After skills: an npm tarball whose root folder is the package (`@types/*` use the name, not
    #: `package/`). Only a `.tgz` itself: a directory with a `package.json` in it is not a release.
    _NPM_NAMED_ROOT: ClassVar[re.Pattern[str]] = re.compile(r"^[^/]+/package\.json$")
    #: Last, after skills: nearly every repository has workflows.
    _ACTIONS: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[^/]+/)?(?:action\.ya?ml|\.github/workflows/[^/]+\.ya?ml)$"
    )
    _MCP: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"@modelcontextprotocol/sdk|[\"']mcp(?:\[cli\])?[>=<~\"' ]|fastmcp"
    )

    @staticmethod
    def floored(finding: Finding, floor: frozenset[str]) -> bool:
        """Never re-graded: anything that is not a code finding, known-malware intel, and the rules
        the model ships as malicious on their own (they fired on no benign unit of its training
        half, `bench/model/verdict_train.py`)."""
        if not VerdictFeatures.is_code(finding.rule_id):
            return True
        return finding.rule_id in floor and finding.confidence in Verdict.FLOOR_CONFIDENCE

    @staticmethod
    def area(
        names: Sequence[str],
        manifests: dict[str, bytes],
        package: dict[str, float],
        rules: dict[str, int],
    ) -> str:
        """Which line a package answers to: an agent skill, an MCP server, a package of a registry
        recognised by its layout (npm, PyPI, Open VSX, `_ECOSYSTEMS`, `_ACTIONS`), or any other.

        Benign skills, MCP servers and libraries of each registry carry different findings by
        nature, so each has its own line, set on its own benign units. Anything not recognised
        answers to the strictest line, so a wrong guess can only make the verdict more cautious.
        """
        if any(rule.startswith("SUSPECT.MCP.") for rule in rules) or any(
            Verdict._MCP.search(data) for data in manifests.values()
        ):
            return "mcp"
        # A registry package that also ships a skill is still judged as a package of its registry.
        # The outermost archive only: what is bundled inside it is not what it is.
        inner = [parts[-1] for parts in (n.split("!") for n in names) if len(parts) <= 2]
        if any(n in ("extension.vsixmanifest", "extension/package.json") for n in inner):
            return "openvsx"
        if "package/package.json" in inner:
            return "npm"
        if any(Verdict._PYPI.match(n) for n in inner):
            return "pypi"
        for ecosystem, layout in Verdict._ECOSYSTEMS:
            if any(layout.match(n) for n in inner):
                return ecosystem
        if package.get("skill"):
            return "skill"
        if any(
            len(parts) == 2
            and parts[0].endswith(".tgz")
            and Verdict._NPM_NAMED_ROOT.match(parts[1])
            for parts in (n.split("!") for n in names)
        ):
            return "npm"
        if any(Verdict._ACTIONS.match(n) for n in inner):
            return "actions"
        return Verdict.FALLBACK

    @staticmethod
    def _lowers(
        rule_id: str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        *,
        score: float,
        block: float,
        liftable: bool,
        floor: frozenset[str],
        keep: frozenset[str],
    ) -> bool:
        """Whether the package verdict lowers this finding below the gate. The one lowering
        decision the scanner (`decide`) and the trainer (`bench/model/verdict_train.py`) both make,
        so what is measured is what ships. A finding is lowered only in a liftable area whose score
        clears the line, and never when it is kept as untrained (`keep`), floored, or is not a code
        finding already at or below a warning."""
        if score >= block or not liftable:
            return False
        if rule_id in keep or not VerdictFeatures.is_code(rule_id):
            return False
        if rule_id in floor and confidence in Verdict.FLOOR_CONFIDENCE:
            return False
        return severity > Severity.MEDIUM or category is Category.MALICIOUS

    @staticmethod
    def decide(
        findings: list[Finding],
        paths_sizes: Sequence[tuple[str, int]],
        manifests: dict[str, bytes],
        sources: Sequence[tuple[str, bytes]] = (),
        profile: dict[str, float] | None = None,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """Findings re-graded by the package verdict, and the verdict to report.

        `profile` is what the code that runs on its own can do (`Engine._capability_profile`),
        read as package facts beside the rest."""
        rules = VerdictFeatures.rules(findings)
        package = {**VerdictFeatures.package(paths_sizes, manifests, sources), **(profile or {})}
        Verdict._skill_claim(package)
        area = Verdict.area([p for p, _ in paths_sizes], manifests, package, rules)
        # The one record the model reads, versioned (`decide/feature_schema`): every input a score
        # reads, so a score can be reproduced from it, and what a fit trains on.
        features = FeatureRecord.of(findings, package)
        summary: dict[str, Any] = {
            "rules": rules,
            "package": package,
            "area": area,
            "features": {"schema": FeatureSchema.current(), "values": features},
        }
        model = VerdictModel.load()
        if model is None:
            return findings, summary
        # The second review (`intel/registry_record.py`): where the registry's record of this
        # release was acquired, its own trees score the package -- content-free malware has no
        # finding for the content verdict to weigh. It may add a block, never lift one.
        scored = VerdictModel.inputs(model, features)
        registry = model.get("registry")
        reviewed = (
            registry is not None and package.get("reg_known") and area in registry.get("areas", {})
        )
        if not rules and not reviewed:
            return findings, summary
        # `reviewed` holds only with a registry section; said again so the type is known here.
        if reviewed and registry is not None:
            summary.update(
                registry_score=round(VerdictModel.score(registry, scored), 4),
                registry_block=float(registry["areas"][area]),
            )
        if not rules:
            return findings, summary
        if "scope" in model and area not in model["scope"]:
            # A model judges only the ecosystems it was trained and measured on; every other
            # package keeps its findings exactly as the rules graded them.
            return findings, summary
        # An area with trees of its own (agent skills read nothing like libraries) is scored by them.
        score = VerdictModel.score(model.get("by_area", {}).get(area, model), scored)
        areas = model["areas"]
        block = float(areas.get(area, areas[Verdict.FALLBACK]))
        summary.update(score=round(score, 4), block=block, model=model.get("version", ""))
        # The model lowers a block only in an area it was trained to separate (`lift_areas`: the
        # allowlist of areas with enough training malware -- the shipped model lists `npm` and
        # `mcp`). Every other area -- `skill`, `package` and the fallback included -- is add-only: it
        # may add a block, never lift one (review 98, the G7 actions regression came from lifting an
        # untrained `package` row). An older model without the allowlist keeps the former denylist.
        lift_areas = model.get("lift_areas")
        liftable = (
            area in lift_areas if lift_areas is not None else area not in model.get("add_only", ())
        )
        floor = frozenset(model["floor"])
        keep = frozenset(model.get("keep", ()))
        out: list[Finding] = []
        Verdict._graded_findings(findings, score, block, liftable, floor, keep, area, out)
        return out, summary

    @staticmethod
    def _skill_claim(package: dict[str, float]) -> None:
        """What a skill says it is, from its front matter, for the intent comparison."""
        if package.get("skill_front_matter"):
            # The skill's claim beside what its scripts can do (`VerdictFeatures._skill_claim`).
            reaches = {
                name[len("agent_can_") :]
                for name, v in package.items()
                if name.startswith("agent_can_") and v
            }
            package["skill_unclaimed_network"] = float(
                bool(reaches & {"egress", "network"}) and not package.get("skill_claims_network")
            )
            package["skill_unclaimed_credentials"] = float(
                "credential" in reaches and not package.get("skill_claims_credentials")
            )
            package["skill_unclaimed_process"] = float(
                bool(reaches & {"spawn", "execute", "runs_download"})
                and not package.get("skill_claims_shell")
            )

    @staticmethod
    def _graded_findings(
        findings: list[Finding],
        score: float,
        block: float,
        liftable: bool,
        floor: frozenset[Any],
        keep: frozenset[Any],
        area: str,
        out: list[Finding],
    ) -> None:
        """The findings that decide the verdict, each with what it contributes."""
        for finding in findings:
            if Verdict._lowers(
                finding.rule_id,
                finding.severity,
                finding.confidence,
                finding.category,
                score=score,
                block=block,
                liftable=liftable,
                floor=floor,
                keep=keep,
            ):
                finding = replace(
                    finding,
                    severity=min(finding.severity, Severity.MEDIUM),
                    category=Category.SUSPICIOUS,
                    message=finding.message
                    + f" Held as a warning by the package verdict: {score:.2f} against a blocking "
                    f"line of {block:.2f} for {area}, from every finding in the package and what "
                    "kind of package it is.",
                )
            out.append(finding)
