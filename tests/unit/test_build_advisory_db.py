"""The filter that decides what ships in the wheel versus what a sync fetches.

`scripts/build_advisory_db.py --full` bypasses this; the default does not,
and the default is what every release actually bundles. Loaded via
`importlib.util` rather than imported normally, the same way
`test_package_intel.py` loads `refresh_package_intel.py` -- it is a script,
not a package module.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from cordon_scanner.intel.advisories import Advisory


def _script():
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "build_advisory_db", root / "scripts" / "build_advisory_db.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestIsHighValue:
    def test_a_critical_vulnerability_is_kept(self) -> None:
        script = _script()
        advisory = Advisory(
            ecosystem="npm", name="x", introduced="1.0.0", fixed="2.0.0", severity="critical"
        )
        assert script._is_high_value(advisory)

    def test_a_high_vulnerability_is_kept(self) -> None:
        script = _script()
        advisory = Advisory(
            ecosystem="npm", name="x", introduced="1.0.0", fixed="2.0.0", severity="high"
        )
        assert script._is_high_value(advisory)

    def test_a_medium_vulnerability_is_dropped(self) -> None:
        script = _script()
        advisory = Advisory(
            ecosystem="npm", name="x", introduced="1.0.0", fixed="2.0.0", severity="medium"
        )
        assert not script._is_high_value(advisory)

    def test_a_low_vulnerability_is_dropped(self) -> None:
        script = _script()
        advisory = Advisory(
            ecosystem="npm", name="x", introduced="1.0.0", fixed="2.0.0", severity="low"
        )
        assert not script._is_high_value(advisory)

    def test_an_unrated_vulnerability_is_dropped(self) -> None:
        """Unrated is not the same claim as low, but it also is not a claim
        this filter can act on -- see `Advisory.severity`'s own docstring."""
        script = _script()
        advisory = Advisory(ecosystem="npm", name="x", introduced="1.0.0", fixed="2.0.0")
        assert not script._is_high_value(advisory)

    def test_a_malicious_entry_is_kept_regardless_of_severity(self) -> None:
        script = _script()
        advisory = Advisory(
            ecosystem="npm", name="x", versions=("6.6.6",), malicious=True, severity=""
        )
        assert script._is_high_value(advisory)
