"""Reads one named environment variable. Imported by setup.py, so it carries
install-hook context -- and must still produce nothing, because reading a named
variable is what a build does."""

import os

VERSION = os.environ.get("PKG_VERSION", "1.0.0")
