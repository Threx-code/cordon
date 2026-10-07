"""VEX statements a scan is given: "this vulnerability does not affect this product".

A supplier's analysis -- OpenVEX, CycloneDX VEX or a CSAF 2.0 VEX document -- that a vulnerability in a component they ship
is not exploitable in it, or is fixed. `--vex PATH` applies those statements: a matching
vulnerability finding is marked suppressed with the statement's status, justification and source,
never dropped, so the report still says what was ruled out and on whose word.

Operator-supplied only, like `--baseline`: a scan target cannot vouch for its own vulnerabilities.
Only vulnerability findings are affected; a statement cannot silence malware or a secret.

Matching is by vulnerability (the advisory id or any CVE it names) and product (a purl; a statement
naming a package without a version covers every version, as both formats allow).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.core.models import Category, Suppression

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Finding

#: Statuses that rule a vulnerability out. `affected` and `under_investigation` rule nothing out.
RULED_OUT: Final = frozenset({"not_affected", "fixed", "false_positive", "resolved"})
_IDENTIFIER: Final = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|[A-Z]+-CVE-\d{4}-\d+)\b"
)
MAX_BYTES: Final = 32 << 20


class VexError(ValueError):
    """A VEX document could not be read. Safe to show."""


@dataclass(frozen=True)
class Statement:
    vulnerabilities: frozenset[str]
    products: tuple[str, ...]
    status: str
    justification: str
    detail: str
    source: str

    def covers(self, identifiers: set[str], purl: str) -> bool:
        if not (self.vulnerabilities & identifiers):
            return False
        if not self.products:
            return True
        bare = purl.split("?", 1)[0].lower()
        unversioned = bare.rsplit("@", 1)[0] if "@" in bare.rsplit("/", 1)[-1] else bare
        for product in self.products:
            wanted = product.split("?", 1)[0].lower()
            if wanted in (bare, unversioned):
                return True
        return False


class VexDocuments:
    """Statements read from OpenVEX, CycloneDX VEX and CSAF 2.0 documents."""

    @staticmethod
    def load(paths: Iterable[str]) -> list[Statement]:
        statements: list[Statement] = []
        for raw in paths:
            path = Path(raw)
            try:
                if path.stat().st_size > MAX_BYTES:
                    raise VexError(f"{path}: larger than {MAX_BYTES} bytes")
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise VexError(f"{path}: {exc}") from exc
            statements.extend(VexDocuments.parse(document, str(path)))
        return statements

    @staticmethod
    def parse(document: Any, source: str) -> list[Statement]:
        if not isinstance(document, dict):
            raise VexError(f"{source}: not a VEX document")
        header = document.get("document")
        if isinstance(header, dict) and str(header.get("csaf_version", "")).startswith("2."):
            return VexDocuments._csaf(document, source)
        if isinstance(document.get("statements"), list):  # OpenVEX
            return VexDocuments._openvex(document, source)
        if isinstance(document.get("vulnerabilities"), list):  # CycloneDX
            return VexDocuments._cyclonedx(document, source)
        raise VexError(
            f"{source}: neither OpenVEX (`statements`), CycloneDX (`vulnerabilities`) nor CSAF 2.0 (`document.csaf_version`)"
        )

    @staticmethod
    def _names(*values: Any) -> frozenset[str]:
        found: set[str] = set()
        for value in values:
            if isinstance(value, str):
                found.update(m.group(0).upper() for m in _IDENTIFIER.finditer(value.upper()))
                found.add(value.strip().upper())
            elif isinstance(value, list):
                found |= VexDocuments._names(*value)
        return frozenset(v for v in found if v)

    @staticmethod
    def _openvex(document: dict[str, Any], source: str) -> list[Statement]:
        out: list[Statement] = []
        for item in document["statements"]:
            if not isinstance(item, dict):
                continue
            vulnerability = item.get("vulnerability")
            if isinstance(vulnerability, dict):
                names = VexDocuments._names(
                    vulnerability.get("name"),
                    vulnerability.get("@id"),
                    vulnerability.get("aliases"),
                )
            else:
                names = VexDocuments._names(vulnerability)
            products = []
            for product in item.get("products") or ():
                if isinstance(product, dict):
                    identifiers = product.get("identifiers") or {}
                    products.append(str(identifiers.get("purl") or product.get("@id") or ""))
                    products += [
                        str(s.get("@id") or (s.get("identifiers") or {}).get("purl") or "")
                        for s in product.get("subcomponents") or ()
                        if isinstance(s, dict)
                    ]
                elif isinstance(product, str):
                    products.append(product)
            out.append(
                Statement(
                    vulnerabilities=names,
                    products=tuple(p for p in products if p.startswith("pkg:")),
                    status=str(item.get("status") or ""),
                    justification=str(item.get("justification") or ""),
                    detail=str(item.get("impact_statement") or item.get("status_notes") or ""),
                    source=source,
                )
            )
        return out

    @staticmethod
    def _cyclonedx(document: dict[str, Any], source: str) -> list[Statement]:
        out: list[Statement] = []
        for item in document["vulnerabilities"]:
            if not isinstance(item, dict):
                continue
            raw_analysis = item.get("analysis")
            analysis: dict[str, Any] = raw_analysis if isinstance(raw_analysis, dict) else {}
            names = VexDocuments._names(
                item.get("id"),
                [r.get("id") for r in item.get("references") or () if isinstance(r, dict)],
            )
            products = [
                str(a.get("ref") or "")
                for a in item.get("affects") or ()
                if isinstance(a, dict) and str(a.get("ref") or "").startswith("pkg:")
            ]
            out.append(
                Statement(
                    vulnerabilities=names,
                    products=tuple(products),
                    status=str(analysis.get("state") or ""),
                    justification=str(analysis.get("justification") or ""),
                    detail=str(analysis.get("detail") or ""),
                    source=source,
                )
            )
        return out

    #: CSAF product status -> the status OpenVEX and CycloneDX use for it.
    CSAF_STATUS: Final = {
        "known_not_affected": "not_affected",
        "fixed": "fixed",
        "first_fixed": "fixed",
        "known_affected": "affected",
        "first_affected": "affected",
        "last_affected": "affected",
        "under_investigation": "under_investigation",
    }

    @staticmethod
    def _csaf_products(tree: Any) -> dict[str, str]:
        """`product_id -> purl` from a CSAF product tree: its branches, its full product names, and
        a relationship's combined product, which stands for the component it names."""
        purls: dict[str, str] = {}

        def read(product: Any) -> None:
            if isinstance(product, dict) and isinstance(product.get("product_id"), str):
                helper = product.get("product_identification_helper")
                purl = helper.get("purl") if isinstance(helper, dict) else None
                if isinstance(purl, str) and purl.startswith("pkg:"):
                    purls[product["product_id"]] = purl

        pending = [tree] if isinstance(tree, dict) else []
        visited = 0
        while pending and visited < 100_000:
            node = pending.pop()
            visited += 1
            read(node.get("product"))
            for product in node.get("full_product_names") or ():
                read(product)
            pending.extend(b for b in node.get("branches") or () if isinstance(b, dict))
        for relation in (tree.get("relationships") or ()) if isinstance(tree, dict) else ():
            if not isinstance(relation, dict):
                continue
            combined = relation.get("full_product_name")
            component = purls.get(str(relation.get("product_reference")))
            if (
                isinstance(combined, dict)
                and isinstance(combined.get("product_id"), str)
                and component
            ):
                purls.setdefault(combined["product_id"], component)
        return purls

    @staticmethod
    def _csaf(document: dict[str, Any], source: str) -> list[Statement]:
        purls = VexDocuments._csaf_products(document.get("product_tree"))
        out: list[Statement] = []
        for item in document.get("vulnerabilities") or ():
            if not isinstance(item, dict):
                continue
            names = VexDocuments._names(
                item.get("cve"),
                [i.get("text") for i in item.get("ids") or () if isinstance(i, dict)],
            )
            if not names:
                continue
            justifications: dict[str, str] = {}
            for flag in item.get("flags") or ():
                if isinstance(flag, dict) and isinstance(flag.get("label"), str):
                    for product in flag.get("product_ids") or ():
                        justifications[str(product)] = flag["label"]
            impacts: dict[str, str] = {}
            for threat in item.get("threats") or ():
                if (
                    isinstance(threat, dict)
                    and threat.get("category") == "impact"
                    and isinstance(threat.get("details"), str)
                ):
                    for product in threat.get("product_ids") or ():
                        impacts[str(product)] = threat["details"]
            raw_statuses = item.get("product_status")
            statuses: dict[str, Any] = raw_statuses if isinstance(raw_statuses, dict) else {}
            for csaf_status, status in VexDocuments.CSAF_STATUS.items():
                for product in statuses.get(csaf_status) or ():
                    purl = purls.get(str(product))
                    if purl is None:
                        continue
                    out.append(
                        Statement(
                            vulnerabilities=names,
                            products=(purl,),
                            status=status,
                            justification=justifications.get(str(product), ""),
                            detail=impacts.get(str(product), ""),
                            source=source,
                        )
                    )
        return out

    @staticmethod
    def identifiers_of(finding: Finding) -> set[str]:
        text = " ".join(
            [
                finding.message,
                finding.explanation.summary if finding.explanation else "",
                *finding.references,
            ]
        )
        return {m.group(0).upper() for m in _IDENTIFIER.finditer(text.upper())}

    @staticmethod
    def apply(findings: Iterable[Finding], statements: list[Statement]) -> tuple[Finding, ...]:
        ruling = [s for s in statements if s.status in RULED_OUT]
        out: list[Finding] = []
        for finding in findings:
            if (
                finding.category is not Category.VULNERABLE
                or finding.suppressed is not None
                or not finding.location.package
            ):
                out.append(finding)
                continue
            identifiers = VexDocuments.identifiers_of(finding)
            match = next(
                (s for s in ruling if s.covers(identifiers, finding.location.package)), None
            )
            if match is None:
                out.append(finding)
                continue
            why = match.status + (f" ({match.justification})" if match.justification else "")
            detail = f": {match.detail}" if match.detail else ""
            out.append(
                finding.with_suppression(
                    Suppression(
                        rule=finding.rule_id,
                        path=finding.location.path,
                        justification=f"VEX {why} per {match.source}{detail}",
                        expires="9999-12-31",
                        approved_by="vex",
                    )
                )
            )
        return tuple(out)


__all__ = ["RULED_OUT", "Statement", "VexDocuments", "VexError"]
