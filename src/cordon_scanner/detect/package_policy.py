"""The organisation's own allow and deny lists, for packages and for licences.

`detect/license.py` reports what is copyleft, which is a fact about an identifier. This applies a
decision: the packages and licences an organisation has said may and may not be used (`policy:
packages:` and `policy: licenses:` in the configuration, merged so a repository's file can only
tighten what the organisation set).

```
  policy:
    packages:
      deny:  ["npm:event-stream", "pypi:pycrypto", "pkg:npm/lodash@4.17.20"]
      allow: []                       # set: nothing else may be used
    licenses:
      deny:  [AGPL-3.0-only, network_copyleft]
      allow: [MIT, Apache-2.0, BSD-3-Clause, ISC]
      unknown: report                 # allow | report | deny
```

A pattern is `ecosystem:name` with `*` wildcards, optionally `@version`, or a purl prefix. A licence
entry is an SPDX identifier or a category (`permissive`, `weak_copyleft`, `copyleft`,
`network_copyleft`, `unknown`). An SPDX expression is allowed when one of its `OR` branches is
wholly allowed, and denied when every branch holds a denied licence.

A licence this cannot establish is never approved: with an allow list set it is at least reported
(`POLICY.LICENSE.UNKNOWN.001`), because "no licence data offline" and "an approved licence" are not
the same answer. The project's own code and platform requirements are not packages and are not
judged.
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from cordon_scanner.core import references
from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Scope,
    Severity,
)
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.intel.licenses import LicenseCategory, LicenseClassifier

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency
    from cordon_scanner.detect.base import ScanContext, Unit

PACKAGE_DENIED_RULE = "POLICY.PACKAGE.DENIED.001"
PACKAGE_NOT_ALLOWED_RULE = "POLICY.PACKAGE.NOT_ALLOWED.001"
LICENSE_DENIED_RULE = "POLICY.LICENSE.DENIED.001"
LICENSE_NOT_ALLOWED_RULE = "POLICY.LICENSE.NOT_ALLOWED.001"
LICENSE_UNKNOWN_RULE = "POLICY.LICENSE.UNKNOWN.001"
CATEGORIES = frozenset(c.value for c in LicenseCategory)


class PackagePatterns:
    @staticmethod
    def matches(dependency: Dependency, pattern: str) -> bool:
        text = pattern.strip()
        if not text:
            return False
        if text.startswith("pkg:"):
            purl = dependency.purl.lower()
            wanted = text.lower()
            return (
                purl == wanted or purl.startswith(wanted + "@") or fnmatch.fnmatchcase(purl, wanted)
            )
        ecosystem, sep, rest = text.partition(":")
        if not sep:
            ecosystem, rest = "*", text
        name, _, version = rest.rpartition("@") if "@" in rest.lstrip("@") else (rest, "", "")
        if not name:
            name, version = rest, ""
        if not fnmatch.fnmatchcase(dependency.ecosystem.lower(), ecosystem.lower()):
            return False
        if not fnmatch.fnmatchcase(dependency.name.lower(), name.lower()):
            return False
        return not version or (dependency.version or "") == version


class LicenceExpressions:
    """Evaluate a declared licence against allow and deny lists."""

    @staticmethod
    def _atom_matches(atom: str, entries: tuple[str, ...]) -> bool:
        normalized = LicenseClassifier.normalize(atom) or atom.strip()
        category = LicenseClassifier.classify(atom).value
        for entry in entries:
            if entry in CATEGORIES:
                if entry == category:
                    return True
            elif entry.lower() == normalized.lower() or entry.lower() == atom.strip().lower():
                return True
        return False

    @staticmethod
    def branches(expression: str) -> list[list[str]]:
        """The expression as alternatives (OR) of conjunctions (AND), `WITH` kept on its base."""
        text = expression.strip().strip("()")
        alternatives = LicenseClassifier._split_top_level(text, "OR") or [text]
        out: list[list[str]] = []
        for alternative in alternatives:
            part = alternative.strip().strip("()")
            atoms = LicenseClassifier._split_top_level(part, "AND") or [part]
            out.append(
                [
                    (LicenseClassifier._split_top_level(a.strip().strip("()"), "WITH") or [a])[0]
                    .strip()
                    .strip("()")
                    for a in atoms
                ]
            )
        return out

    @staticmethod
    def allowed(expression: str, allow: tuple[str, ...]) -> bool:
        return any(
            all(LicenceExpressions._atom_matches(a, allow) for a in branch)
            for branch in LicenceExpressions.branches(expression)
        )

    @staticmethod
    def denied(expression: str, deny: tuple[str, ...]) -> bool:
        return all(
            any(LicenceExpressions._atom_matches(a, deny) for a in branch)
            for branch in LicenceExpressions.branches(expression)
        )


class PackagePolicyDetector(BaseDetector):
    """Applies `policy.packages` and `policy.licenses` to every resolved or declared dependency."""

    id = "package-policy"
    version = "0.1.0"
    categories = frozenset({Category.POLICY})
    operator_enabled = True
    """Silent until an organisation configures package or licence lists; exercised in
    `tests/conformance/test_universal.py::TestPolicyLists` for every ecosystem."""
    requires = DetectorRequirements(content=False, dependencies=True)

    def applicable(self, ctx: ScanContext) -> bool:
        policy = ctx.config.policy
        return bool(ctx.dependencies) and bool(
            policy.package_deny
            or policy.package_allow
            or policy.license_deny
            or policy.license_allow
            or policy.license_unknown != "allow"
        )

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        def rule(
            rule_id: str, title: str, severity: Severity, message: str, remediation: str
        ) -> DeclaredRule:
            return DeclaredRule(
                id=rule_id,
                title=title,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                category=Category.POLICY,
                detector=PackagePolicyDetector.id,
                message=message,
                # Package lists are the S2C2F's ingestion governance; a licence verdict also rests
                # on the SPDX expression grammar it is evaluated in.
                references=(references.OPENSSF_S2C2F,)
                if rule_id.startswith("POLICY.PACKAGE.")
                else (references.SPDX_LICENSE_EXPRESSIONS, references.OPENSSF_S2C2F),
                remediation=remediation,
            )

        return (
            rule(
                PACKAGE_DENIED_RULE,
                "Dependency on a package the policy denies",
                Severity.HIGH,
                "The organisation's policy lists this package as one that must not be used.",
                "Remove it, or replace it with an approved alternative.",
            ),
            rule(
                PACKAGE_NOT_ALLOWED_RULE,
                "Dependency outside the policy's allowed packages",
                Severity.MEDIUM,
                "The organisation's policy allows only listed packages, and this one is not listed.",
                "Have it reviewed and added to the allowed list, or remove it.",
            ),
            rule(
                LICENSE_DENIED_RULE,
                "Dependency under a licence the policy denies",
                Severity.HIGH,
                "The dependency's licence, under every choice its expression offers, is one the policy denies.",
                "Replace the dependency, or obtain an approval recorded as a suppression.",
            ),
            rule(
                LICENSE_NOT_ALLOWED_RULE,
                "Dependency under a licence outside the allowed list",
                Severity.MEDIUM,
                "No choice the dependency's licence expression offers is wholly on the policy's allowed list.",
                "Have the licence reviewed and added, or replace the dependency.",
            ),
            rule(
                LICENSE_UNKNOWN_RULE,
                "Dependency whose licence could not be established",
                Severity.LOW,
                "No licence data was available for the dependency, or what it declares is not a licence this "
                "scanner can classify. Unknown is not approved.",
                "Establish the licence (the registry, the package's own files) and record it, or allow it explicitly.",
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit):
            return ()
        policy = ctx.config.policy
        findings: list[Finding] = []
        for dependency in unit.dependencies:
            if dependency.local or dependency.scope is Scope.PLATFORM:
                continue
            # Go's standard library arrives with the toolchain: nobody chooses it from a list.
            if not (dependency.ecosystem == "gomod" and dependency.name == "stdlib"):
                findings.extend(self._packages(dependency, ctx))
            findings.extend(self._licences(dependency, ctx))
        del policy
        return findings

    def _packages(self, dependency: Dependency, ctx: ScanContext) -> Iterable[Finding]:
        policy = ctx.config.policy
        denied = next(
            (p for p in policy.package_deny if PackagePatterns.matches(dependency, p)), None
        )
        if denied is not None:
            yield self._finding(
                PACKAGE_DENIED_RULE,
                Severity.HIGH,
                dependency,
                ctx,
                f"{dependency.name}{self._at(dependency)} matches {denied!r}, which the policy denies.",
                "Remove it, or replace it with an approved alternative.",
            )
            return
        if policy.package_allow and not any(
            PackagePatterns.matches(dependency, p) for p in policy.package_allow
        ):
            yield self._finding(
                PACKAGE_NOT_ALLOWED_RULE,
                Severity.MEDIUM,
                dependency,
                ctx,
                f"{dependency.name}{self._at(dependency)} is not among the packages the policy allows.",
                "Have it reviewed and added to the allowed list, or remove it.",
            )

    def _licences(self, dependency: Dependency, ctx: ScanContext) -> Iterable[Finding]:
        policy = ctx.config.policy
        declared = (dependency.license or "").strip()
        known = (
            bool(declared) and LicenseClassifier.classify(declared) is not LicenseCategory.UNKNOWN
        )
        if not known:
            handling = policy.license_unknown
            if handling == "allow" and policy.license_allow:
                handling = "report"  # with an allow list, unknown is never approved
            if "unknown" in policy.license_deny:
                handling = "deny"
            if handling != "allow":
                what = (
                    f"declares {declared!r}, which is not a licence this scanner can classify"
                    if declared
                    else "has no licence data available"
                )
                yield self._finding(
                    LICENSE_UNKNOWN_RULE,
                    Severity.HIGH if handling == "deny" else Severity.LOW,
                    dependency,
                    ctx,
                    f"{dependency.name}{self._at(dependency)} {what}. Unknown is not approved.",
                    "Establish the licence and record it, or allow it explicitly.",
                )
            return
        if policy.license_deny and LicenceExpressions.denied(declared, policy.license_deny):
            yield self._finding(
                LICENSE_DENIED_RULE,
                Severity.HIGH,
                dependency,
                ctx,
                f"{dependency.name}{self._at(dependency)} is licensed {declared!r}, which the policy denies.",
                "Replace the dependency, or obtain an approval recorded as a suppression.",
            )
            return
        if policy.license_allow and not LicenceExpressions.allowed(declared, policy.license_allow):
            yield self._finding(
                LICENSE_NOT_ALLOWED_RULE,
                Severity.MEDIUM,
                dependency,
                ctx,
                f"{dependency.name}{self._at(dependency)} is licensed {declared!r}, which is not on the "
                f"policy's allowed list.",
                "Have the licence reviewed and added, or replace the dependency.",
            )

    @staticmethod
    def _at(dependency: Dependency) -> str:
        return f" {dependency.version}" if dependency.version else ""

    def _finding(
        self,
        rule_id: str,
        severity: Severity,
        dependency: Dependency,
        ctx: ScanContext,
        message: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=Category.POLICY,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(
                path=dependency.declared_in or dependency.project or ".",
                package=dependency.purl,
                project=dependency.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{dependency.purl}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("license", dependency.license or ""),),
            ),
            remediation=remediation,
            explanation=Explanation(summary=message, matched_rule=rule_id),
            risk=ctx.scorer.score(severity, Confidence.CONFIRMED),
            detector=self.id,
            references=(),
            capabilities=(),
        )


__all__ = [
    "LICENSE_DENIED_RULE",
    "LICENSE_NOT_ALLOWED_RULE",
    "LICENSE_UNKNOWN_RULE",
    "PACKAGE_DENIED_RULE",
    "PACKAGE_NOT_ALLOWED_RULE",
    "LicenceExpressions",
    "PackagePatterns",
    "PackagePolicyDetector",
]
