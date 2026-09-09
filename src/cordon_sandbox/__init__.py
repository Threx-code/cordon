"""The runtime-analysis component. Separate from the scanner on purpose.

Cordon's core promise is that it never executes the code it scans, and that
promise is a security property rather than a limitation: running attacker code
is the thing the tool exists to protect people from. This component does the
opposite, deliberately, under isolation, and only when someone asks.

So it is kept apart in every way that matters. It is not imported by the
scanner, not reachable from `cordon-scanner scan`, and not run by any default.
It has its own entry point, and that entry point refuses to do anything without
an explicit flag whose only purpose is to be hard to pass by accident.

**What it exists to see.** The static tiers resolve constant-derived
obfuscation and turn runtime-computed dispatch into a signal of its own. What
neither can decide is behaviour that only exists while the code runs -- a target
decoded from a network response, logic gated on a fetched value. That residual
is not a gap in the implementation, it is Rice's theorem, and the only tool that
observes it is one that runs the code.

**What it refuses to do.** If isolation cannot be established, it does not run
the code. Not with a warning, not with reduced isolation, not on the host: it
exits and says why. A sandbox that degrades to running untrusted code directly
when its backend is missing is worse than no sandbox, because the person who
asked for it believes they are protected.
"""

from cordon_sandbox.isolation import Backend, IsolationError, available_backend

__all__ = ["Backend", "IsolationError", "available_backend"]
