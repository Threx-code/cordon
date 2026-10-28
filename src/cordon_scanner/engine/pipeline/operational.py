"""Findings about the scan itself: a file that could not be read, an archive member refused, a check
that could not run.

Every degradation produces one of these. A file that was not examined is indistinguishable in the
output from one that was examined and found clean, so coverage loss is always stated, never
inferred, and no reporting threshold may hide it.
"""

from __future__ import annotations

__all__ = []
