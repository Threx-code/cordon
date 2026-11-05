"""Which scope a locked package has, from the scopes of the declarations that reach it: npm's rule
for its `dev` and `optional` flags, applied to every lockfile that records no scope of its own.
"""

from __future__ import annotations

from cordon_scanner.foundation.models import Scope


class LockScopes:
    """Which scope a package has, from the scopes of the declarations that reach it.

    A package reached from any runtime declaration is runtime, whatever else also reaches it; one
    reached only through optional declarations is optional; only through dev ones, dev. pnpm 9 and
    Yarn record no per-package `dev` flag, so the scope is the graph's answer, not a field's.
    """

    #: When several kinds of declaration reach one package, the one closest to what ships wins:
    #: anything reached at runtime is runtime; a build tool reached by tests is still a build tool.
    ORDER: tuple[Scope, ...] = (
        Scope.RUNTIME,
        Scope.PEER,
        Scope.OPTIONAL,
        Scope.BUILD,
        Scope.TOOL,
        Scope.TEST,
        Scope.DEV,
    )

    @staticmethod
    def rank(scope: Scope) -> int:
        """Position in `ORDER`; a scope outside it (platform) ranks last."""
        return LockScopes.ORDER.index(scope) if scope in LockScopes.ORDER else len(LockScopes.ORDER)

    @staticmethod
    def propagate(
        roots: dict[str, set[Scope]], edges: dict[str, set[str]], limit: int = 2_000_000
    ) -> dict[str, Scope]:
        reached: dict[str, set[Scope]] = {key: set(scopes) for key, scopes in roots.items()}
        queue = list(roots)
        steps = 0
        while queue and steps < limit:
            steps += 1
            key = queue.pop()
            for child in edges.get(key, ()):
                known = reached.setdefault(child, set())
                missing = reached[key] - known
                if missing:
                    known |= missing
                    queue.append(child)
        return {
            key: next((s for s in LockScopes.ORDER if s in scopes), Scope.RUNTIME)
            for key, scopes in reached.items()
        }


__all__ = ["LockScopes"]
