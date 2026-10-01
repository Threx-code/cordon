"""Whether a declared range admits a release: npm semver ranges and PEP 440 specifiers."""

from __future__ import annotations

import pytest

from cordon_scanner.intel.ranges import admits


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ("^1.11.21", "1.11.22", True),
        ("^1.11.21", "2.0.0", False),
        ("^1.11.21", "1.11.20", False),
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.4", False),
        ("~1.2.3", "1.2.9", True),
        ("~1.2.3", "1.3.0", False),
        ("1.2.x", "1.2.7", True),
        ("1.2", "1.3.0", False),
        ("*", "9.9.9", True),
        ("", "1.0.0", True),
        (">=1.2.0 <1.4.0", "1.3.5", True),
        (">= 1.2.0 < 1.4.0", "1.4.0", False),
        ("1.0.0 - 1.2.0", "1.2.0", True),
        ("1.0.0 - 1.2", "1.2.9", True),
        ("^1.0.0 || ^3.0.0", "3.1.0", True),
        ("^1.0.0 || ^3.0.0", "2.1.0", False),
        ("1.2.3", "1.2.3", True),
        ("=1.2.3", "1.2.4", False),
        ("^1.2.3", "1.3.0-beta.1", False),
        ("^1.2.3-beta.1", "1.2.3-beta.2", True),
        (">1.2", "1.2.9", False),
        (">1.2", "1.3.0", True),
        ("file:../local", "1.0.0", False),
        ("workspace:*", "1.0.0", False),
        ("git+https://github.com/a/b", "1.0.0", False),
    ],
)
def test_npm(spec: str, version: str, expected: bool) -> None:
    assert admits("npm", spec, version) is expected


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        (">=1.0,<2.0", "1.5.0", True),
        (">=1.0,<2.0", "2.0", False),
        ("==1.4.*", "1.4.9", True),
        ("==1.4.*", "1.5.0", False),
        ("!=1.4.2", "1.4.2", False),
        ("~=2.2", "2.9", True),
        ("~=2.2", "3.0", False),
        ("~=1.4.5", "1.4.9", True),
        ("~=1.4.5", "1.5.0", False),
        ("==2.0.0", "2.0.0", True),
        (">=1.0; python_version >= '3.8'", "1.2", True),
        ("garbage", "1.0", False),
    ],
)
def test_pep440(spec: str, version: str, expected: bool) -> None:
    assert admits("pypi", spec, version) is expected


def test_other_ecosystems_answer_no() -> None:
    assert admits("cargo", "^1.0", "1.0.1") is False
