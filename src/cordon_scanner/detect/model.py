"""Cordon's own model, asked about the packages a scan holds. Runs only with `--model`.

The scoring happens after the scan (`cli/main.py`, `CommandLine._with_model`): the packages are
found, their features computed here on the scanning machine, and a Cordon model server -- Cordon
Cloud, or one inside the organisation -- scores them. This detector inspects no file itself; it
declares the rules that step reports, so `rules show` and the rule reference know them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core import references as ref
from cordon_scanner.core.models import Category, Confidence, Severity
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Finding
    from cordon_scanner.detect.base import ScanContext, Unit

MALICIOUS_PACKAGE = "SUSPECT.MODEL.MALICIOUS_PACKAGE.001"
UNAVAILABLE = "OPERATIONAL.MODEL.UNAVAILABLE"


class ModelDetector(BaseDetector):
    id = "model"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=False)

    def applicable(self, ctx: ScanContext) -> bool:
        return False

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        return ()

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=MALICIOUS_PACKAGE,
                title="Cordon's model judges a package malicious",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ModelDetector.id,
                message=(
                    "Cordon's detection model, trained on tens of thousands of real malicious and "
                    "legitimate packages, scores this package as malicious from what its code does and "
                    "how it is built. A model's verdict is evidence, not proof: read the findings "
                    "beside it and the package's code before trusting it."
                ),
                remediation=(
                    "Do not install or run it until it has been reviewed. If it is a dependency, pin "
                    "the last release you have reviewed, or remove it."
                ),
                references=(ref.EMBEDDED_MALICIOUS_CODE, ref.ATTACK_MALICIOUS_FILE),
            ),
        )
