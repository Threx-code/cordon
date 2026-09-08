"""Support `python -m cordon`.

Present so the module form works wherever the console script is awkward: a
container without the entry point on PATH, a CI step pinning an interpreter, or
a pre-commit hook running under a specific environment. Without this file that
invocation fails with "cordon is a package and cannot be directly executed",
which reads like a broken installation rather than a missing convenience.
"""

from __future__ import annotations

from cordon.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
