"""Moved to `cordon_scanner.foundation.signatures.ecdsa` (reviews 20-PACKAGE-STRUCTURE.md).

This path is kept for one release (until 0.8.0) so code importing it keeps working. It is the
same module, not a copy: names, private ones included, and patches reach the real one.
"""

import sys

from cordon_scanner.foundation.signatures import ecdsa as _module

sys.modules[__name__] = _module
