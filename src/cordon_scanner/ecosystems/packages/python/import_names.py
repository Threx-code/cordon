"""What a PyPI distribution is imported as, where the two names differ (`beautifulsoup4` is `bs4`).

Ecosystem knowledge, read by the reachability check (`detect/supply/reachability`) and by the
advisory-text reader (`intel/advisories/advisory_text`); it lives here, below both, so neither
reaches up into the other for it (architecture audit F1).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Mapping


class PythonImportNames:
    """The import names of PyPI distributions whose import name differs from their own."""

    #: PyPI distribution names whose import name differs. Without these a real import
    #: would be missed and the finding wrongly lowered. Small and common on purpose:
    #: an unlisted mismatch falls to UNKNOWN (not lowered), which is the safe
    #: direction.
    ALIASES: ClassVar[Mapping[str, tuple[str, ...]]] = MappingProxyType(
        {
            "beautifulsoup4": ("bs4",),
            "pillow": ("PIL",),
            "pyyaml": ("yaml",),
            "python-dateutil": ("dateutil",),
            "scikit-learn": ("sklearn",),
            "msgpack-python": ("msgpack",),
            "opencv-python": ("cv2",),
            "protobuf": ("google",),
            "setuptools": ("setuptools", "pkg_resources"),
            "gitpython": ("git",),
            "pyjwt": ("jwt",),
            "pycryptodome": ("Crypto",),
            "pycryptodomex": ("Cryptodome",),
            "python-jose": ("jose",),
            "python-multipart": ("multipart",),
            "pyopenssl": ("OpenSSL",),
            "python-ldap": ("ldap",),
            "pysaml2": ("saml2",),
            "pymongo": ("pymongo", "bson", "gridfs"),
            "pyzmq": ("zmq",),
            "python-magic": ("magic",),
        }
    )

    @staticmethod
    def aliases(distribution: str) -> tuple[str, ...]:
        """The import names of a normalised distribution name (lower case, `-` for `_`); empty when
        it is imported under its own name."""
        return PythonImportNames.ALIASES.get(distribution, ())


__all__ = ["PythonImportNames"]
