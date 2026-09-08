"""Version constants.

Three versions travel together and each answers a different question, which is
why they are not one number:

``__version__``
    The engine. Changes when code changes.

``RULEPACK_VERSION``
    The bundled rules. Changes when detection content changes, without an engine
    release. Security reviews a rule update; engineering reviews a code update.
    Collapsing these would force one team to sign off on the other's work.

``SCHEMA_VERSION``
    The JSON result format. Consumers pin against this. It changes only on a
    breaking change to the serialised shape, and every reporter derives from the
    same JSON, so one number covers all output formats.
"""

from __future__ import annotations

__version__ = "0.1.0"
RULEPACK_VERSION = "0.1.0"
SCHEMA_VERSION = 1

# Minimum engine version a rule pack may require. Packs declare
# `requires_engine: ">=1.0,<2.0"`; the loader refuses a pack whose requirement
# this engine does not satisfy rather than loading it and silently skipping the
# rules it cannot compile.
ENGINE_API_VERSION = "0.1"

__all__ = [
    "ENGINE_API_VERSION",
    "RULEPACK_VERSION",
    "SCHEMA_VERSION",
    "__version__",
]
