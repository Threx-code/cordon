"""The generated policies: the policy table generated from upstream definitions, loaded from the
package's data with its digests checked, and the severity and confidence names it uses.
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from cordon_scanner.detect.infra.iac import IacPolicy
from cordon_scanner.detect.infra.iac_policies import CURATED, CuratedPolicies
from cordon_scanner.detect.infra.policy_terms import HIGH, LOW, MEDIUM
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import Category, Confidence, Severity
from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths

#: Where the generated half lives, beside the advisory data and for the same
#: reason: it is large, it is regenerated on a schedule rather than edited, and
#: it ships with a metadata sidecar saying what it was built from.
DATA_DIR: Final = PackagePaths.data("detect")

GENERATED_NAME: Final = "iac-policies.json.gz"

GENERATED_META: Final = "iac-policies-meta.json"

GENERATED_DIGESTS: Final = "iac-policies-digests.json"

_REFUSED: set[str] = set()
"""Generated files refused this process because their digest did not match.

Module-level because `generated_rows` is cached and lazy: the check happens on
first use, which is well after the detector was constructed, so the result has
to be readable afterwards rather than returned."""


class GeneratedPolicies:
    """Policies generated from provider schemas, verified against their manifest."""

    @staticmethod
    def refused_files() -> tuple[str, ...]:
        """Generated policy files that were not loaded, for the detector to report."""
        return tuple(sorted(_REFUSED))

    @staticmethod
    def _digests_match(path: Path) -> bool:
        """Whether a file agrees with the manifest shipped beside it.

        An absent manifest is not a failure: a checkout that has never run
        `scripts/build/build_iac_policies.py` has neither the data nor the manifest. A
        manifest that disagrees is something to say out loud -- half a policy set is
        worse than none, because the count still looks healthy.
        """
        try:
            recorded = ScannedJson.loads(
                (path.parent / GENERATED_DIGESTS).read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return True
        if not isinstance(recorded, dict) or path.name not in recorded:
            return True
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest() == str(recorded[path.name])
        except OSError:
            return False

    @staticmethod
    @OneOff.cache
    def generated_rows() -> dict[str, tuple[dict[str, Any], ...]]:
        """The schema-generated policies, grouped by the resource they are about.

        Rows, not `IacPolicy` objects. There are more than a thousand of them and
        each carries patterns to compile, while a scan asks about the handful of
        resource kinds a file actually declares -- so the grouping is built once and
        the objects are built by `IacDetector` for the kinds it meets. A scan with
        no infrastructure in it constructs none of them.

        Missing is normal rather than an error: a checkout where
        `scripts/build/build_iac_policies.py` has not run has the curated table and says
        so through `generated_meta()`.
        """
        path = DATA_DIR / GENERATED_NAME
        if path.exists() and not GeneratedPolicies._digests_match(path):
            # Not read at all. A policy set that has been edited since it was built
            # is not a smaller policy set, it is one whose contents nobody can
            # account for, and loading part of it would report a healthy count.
            _REFUSED.add(path.name)
            return {}
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                rows = json.load(handle)
        except (OSError, ValueError, EOFError, gzip.BadGzipFile):
            return {}
        if not isinstance(rows, list):
            return {}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            for resource in row.get("resources") or ():
                grouped.setdefault(str(resource), []).append(row)
        return {resource: tuple(items) for resource, items in grouped.items()}

    @staticmethod
    @OneOff.cache
    def generated_meta() -> dict[str, Any]:
        """What the generated set was built from, for `rules list` and the report."""
        try:
            return dict(ScannedJson.loads((DATA_DIR / GENERATED_META).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return {}

    @staticmethod
    def policy_from_row(row: dict[str, Any]) -> IacPolicy:
        """Build one generated policy. The shape is the script's output contract."""
        return IacPolicy(
            id=str(row["id"]),
            title=str(row["title"]),
            message=str(row["message"]),
            remediation=str(row["remediation"]),
            severity=_SEVERITY_BY_NAME[str(row["severity"])],
            confidence=_CONFIDENCE_BY_NAME[str(row["confidence"])],
            category=Category.SUSPICIOUS if row["category"] == "suspicious" else Category.POLICY,
            resources=tuple(str(r) for r in row.get("resources") or ()),
            forbid=tuple(str(p) for p in row.get("forbid") or ()),
            require=tuple(str(p) for p in row.get("require") or ()),
            unless=tuple(str(p) for p in row.get("unless") or ()),
            bad=str(row.get("bad", "")),
            good=str(row.get("good", "")),
        )

    @staticmethod
    def generated_policies() -> tuple[IacPolicy, ...]:
        """Every generated policy, built. For the catalogue and the suite, not a scan."""
        seen: dict[str, IacPolicy] = {}
        for rows in GeneratedPolicies.generated_rows().values():
            for row in rows:
                identifier = str(row["id"])
                if identifier not in seen:
                    seen[identifier] = GeneratedPolicies.policy_from_row(row)
        return tuple(seen.values())

    @staticmethod
    @OneOff.cache
    def all_policies() -> tuple[IacPolicy, ...]:
        """Curated plus generated, which is what `rules list` and the matrix show.

        Each policy leaves here carrying its family's references, so a finding and
        a `rules show` answer the same "says who?" without either of them looking
        the table up. Attached here rather than written into 1,081 declarations,
        and attached once: `IacPolicy` is frozen, so this rebuilds rather than
        mutates, and the result is cached because the set does not change.
        """
        return tuple(
            policy
            if policy.references
            else dataclasses.replace(policy, references=CuratedPolicies.references_for(policy.id))
            for policy in CURATED + GeneratedPolicies.generated_policies()
        )


_SEVERITY_BY_NAME: Final[dict[str, Severity]] = {
    "critical": Severity.CRITICAL,
    "high": HIGH,
    "medium": MEDIUM,
    "low": LOW,
    "info": Severity.INFO,
}

_CONFIDENCE_BY_NAME: Final[dict[str, Confidence]] = {
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}


__all__ = ["DATA_DIR", "GENERATED_DIGESTS", "GENERATED_META", "GENERATED_NAME", "GeneratedPolicies"]
