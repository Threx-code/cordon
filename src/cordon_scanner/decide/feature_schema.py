"""The verdict features' schema version: what a training row was computed by, so a fit never mixes rows
whose features mean different things.

The verdict model is trained on rows that scans wrote (`verdict.package` and the findings the
evidence is built from), often by an earlier commit than the one the model ships in. A row is only
usable when its features were computed the way the shipped scanner computes them, so every verdict
record carries `schema`, and a fit refuses rows of any other version.

The version is derived, never bumped by hand, from two things:

- the code that turns a scan's facts into features: the abstract syntax tree of each piece listed
  in `EXTRACTOR`, docstrings removed, so a comment or a docstring edit leaves it alone and any change
  to what is computed moves it;
- the static feature names: the package facts of an empty package, the cosmetic facts the model
  never scores and the coverage rules.

What the detectors find is not part of it. The findings and capability labels a feature is built
from are the scan's facts, checked row by row wherever rows from two commits are compared.

`version(root)` reads the sources under `root`, the package directory of any checkout, so a row
written before this field existed can be stamped with the version of the tree that wrote it.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import json
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.paths import PackagePaths

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from cordon_scanner.foundation.models import Finding


class FeatureSchema:
    """The schema version of the verdict features a tree computes."""

    #: Each piece of the extractor, as (file under the package, dotted name in that file).
    EXTRACTOR: ClassVar[tuple[tuple[str, str], ...]] = (
        ("decide/verdict.py", "VerdictFeatures"),
        ("engine/engine.py", "Engine._capability_profile"),
        ("detect/code/reached_flows.py", "ReachedFlows"),
        ("engine/pipeline/history.py", "History.registry_facts"),
    )
    PREFIX: ClassVar[str] = "fs1-"
    #: Where a piece now lives, when it moved after EXTRACTOR recorded it. The version hashes the
    #: recorded location, not the file: moving code is not a change to the features, so a move must
    #: not refuse every row computed before it. The code itself is still read and hashed.
    MOVED: ClassVar[dict[str, str]] = {
        "decide/verdict.py:VerdictFeatures": "decide/verdict_features.py",
    }

    @staticmethod
    def source(path: str, dotted: str) -> str:
        """The file an EXTRACTOR piece is read from now (`MOVED`), relative to the package."""
        return FeatureSchema.MOVED.get(f"{path}:{dotted}", path)

    @staticmethod
    def version(root: Path | None = None, names: list[str] | None = None) -> str:
        """The version of the features the tree under `root` (a `cordon_scanner` package directory;
        this one by default) computes. `names` are its static feature names (`names()` of that
        tree); computed here when not given."""
        root = PackagePaths.root() if root is None else root
        digest = hashlib.sha256()
        for path, dotted in FeatureSchema.EXTRACTOR:
            node = FeatureSchema._node(root / FeatureSchema.source(path, dotted), dotted)
            digest.update(f"{path}:{dotted}\n".encode())
            digest.update(ast.dump(FeatureSchema._without_docstrings(node)).encode())
        listed = FeatureSchema.names() if names is None else names
        digest.update(json.dumps(sorted(listed)).encode())
        return FeatureSchema.PREFIX + digest.hexdigest()[:16]

    @staticmethod
    @functools.cache
    def current() -> str:
        """This package's version, computed once: the code it is derived from does not change
        under a running process (process-wide by design, not a per-scan cache)."""
        return FeatureSchema.version()

    @staticmethod
    def names() -> list[str]:
        """The static feature names: an empty package's facts, the cosmetic facts and the coverage
        rules' axes."""
        from cordon_scanner.decide.verdict_features import VerdictFeatures

        package = VerdictFeatures.package([], {}, [])
        return sorted(
            {
                *(f"pkg:{name}" for name in package),
                *(f"cosmetic:{name}" for name in VerdictFeatures.COSMETIC),
                *(f"cov:{axis}" for axis in VerdictFeatures.COVERAGE_RULES.values()),
            }
        )

    @staticmethod
    def _node(path: Path, dotted: str) -> ast.AST:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        node: ast.AST = tree
        for part in dotted.split("."):
            found = next(
                (
                    child
                    for child in ast.iter_child_nodes(node)
                    if isinstance(child, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
                    and child.name == part
                ),
                None,
            )
            if found is None:
                raise LookupError(f"{dotted} is not defined in {path}: the extractor list is stale")
            node = found
        return node

    @staticmethod
    def _without_docstrings(node: ast.AST) -> ast.AST:
        """A copy of `node` with every docstring removed, comments being gone already."""
        copy = ast.parse(ast.unparse(node))
        for child in ast.walk(copy):
            if isinstance(
                child, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef | ast.Module
            ):
                body = child.body
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    child.body = body[1:] or [ast.Pass()]
        return copy


class FeatureRecord:
    """The features the verdict model reads, built in one place: what a scan's verdict record
    carries (`verdict.features`) and what a fit trains on. Nothing else reaches the model."""

    @staticmethod
    def of(findings: Iterable[Finding], package: dict[str, float]) -> dict[str, float]:
        """The features of a scan's findings and package facts."""
        from cordon_scanner.decide.verdict_features import VerdictFeatures

        return VerdictFeatures.evidence(
            (
                (f.rule_id, int(f.severity), int(f.confidence), str(f.category), f.location.path)
                for f in findings
            ),
            package,
        )

    @staticmethod
    def read(row: dict[str, Any]) -> tuple[str | None, dict[str, float]]:
        """A training row's (schema, features): its own record, or for a row written before the
        record existed, the same features built from what it recorded (its findings as
        [rule, severity, confidence, category, path, ...] and `verdict.package`), with no schema
        (the row's producer stamp names it)."""
        from cordon_scanner.decide.verdict_features import VerdictFeatures
        from cordon_scanner.foundation.models import Confidence, Severity

        verdict = row.get("verdict") or {}
        record = verdict.get("features")
        if isinstance(record, dict) and isinstance(record.get("values"), dict):
            return record.get("schema"), dict(record["values"])
        return None, VerdictFeatures.evidence(
            (
                (
                    f[0],
                    int(Severity[f[1].upper()]),
                    int(Confidence[f[2].upper()]),
                    f[3],
                    f[4] or "",
                )
                for f in row.get("findings", [])
            ),
            verdict.get("package") or {},
        )


__all__ = ["FeatureRecord", "FeatureSchema"]
