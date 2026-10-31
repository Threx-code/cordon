"""The `crx` module (modules.formats.crx) held to YARA-X 1.21.0's own output, recorded
(data/rule_reference/yarax/crx-1.21.0.json.gz), on the extensions crx_kit writes: CRX2 and CRX3 signed
for real with test keys (RSA, and ECDSA P-256 in CRX3), tampered after signing, locale resolution
(found, missing key, default_locale), and every manifest the reference's typed reader refuses (a
permission that is an object, a field of the wrong type, a duplicated field, a byte-order mark, NaN),
beside headers that are not a CRX. Each file is the same bytes every run, checked by its SHA-256."""

from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.modules.builtin import Builtin
from cordon_scanner.detect.binary.modules.formats.crx import Crx
from cordon_scanner.detect.binary.rule_engine.lang import Rules
from kits.crxkit import CrxKit
from support import ROOT

RECORD: dict[str, Any] = json.loads(
    gzip.decompress((ROOT / "tests/unit/data/rule_reference/yarax/crx-1.21.0.json.gz").read_bytes())
)
CASES = CrxKit.cases()


class Shape:
    @staticmethod
    def reference(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: Shape.reference(x) for k, x in v.items()}
        if isinstance(v, list):
            return [Shape.reference(x) for x in v]
        return v.encode() if isinstance(v, str) else v

    @staticmethod
    def ours(v: Any) -> Any:
        if isinstance(v, dict):
            if v and all(isinstance(k, int) for k in v):
                return [Shape.ours(v[k]) for k in sorted(v)]
            return {
                k: Shape.ours(x)
                for k, x in v.items()
                if not isinstance(x, tuple) and not (isinstance(x, dict) and not x)
            }
        return v


class TestAgainstYaraX:
    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_extension_gives_the_reference_values(self, name: str) -> None:
        recorded = RECORD["crx"][name]
        assert hashlib.sha256(CASES[name]).hexdigest() == recorded["sha256"]
        assert Shape.ours(Crx.data(CASES[name])) == Shape.reference(recorded["values"])


class TestRules:
    def test_the_module_is_built_in(self) -> None:
        assert "crx" in Builtin.modules()

    @pytest.mark.parametrize(
        "condition",
        [
            "crx.is_crx and crx.crx_version == 3",
            "crx.signatures[0].verified and crx.signatures[1].verified",
            'for any p in crx.permissions : (p == "storage")',
            'crx.permhash() == "' + hashlib.sha256(b"tabsstorage").hexdigest() + '"',
            'crx.id == "abababababababababababababababab"',
        ],
    )
    def test_a_condition_reads_each_value(self, condition: str) -> None:
        assert Rules.compile(f'import "crx" rule r {{ condition: {condition} }}').match(CASES["v3"])

    def test_a_tampered_extension_still_reads_with_its_signature_false(self) -> None:
        rules = Rules.compile(
            'import "crx" rule r { condition: crx.is_crx and not crx.signatures[0].verified }'
        )
        assert rules.match(CASES["v3-tampered"])
