"""Asking a public ecosystem reader of a private registry instead.

Every reader that speaks a public registry builds its addresses from that registry's own origin and
sends them through `RegistryHttp.get`. A route set for the current thread changes what that one
function does, and nothing else:

* an address on one of the route's public origins is rewritten to the same path under the private
  registry's base, and carries the operator's credential;
* an address already under the private registry's base carries the credential;
* any other address is refused. A package that lives in a private registry must never be asked
  about at a public one (its name would tell a third party what the organisation depends on), and
  the credential must never leave the registry it was named for.

The path that is asked stays under the base: a name or a version that came from scanned content may
not carry a `.` or `..` segment (also percent-encoded once), an empty segment, a backslash or a
control character into it, since a private server that normalises the path would answer from outside
the repository the credential was named for.

The route is per thread, so scans that run side by side never see each other's. A reader that
handed work to another thread would ask the public registry, with no route, about a private name:
no reader does, and a test starts no thread under any reader while a route is set.
"""

from __future__ import annotations

import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    """One private registry standing in for the public origins of one ecosystem."""

    base: str
    host: str
    authorization: str
    #: Public addresses (an origin, or an origin and a path) the private registry answers in their place, each with the
    #: path under the base it is answered at ("" for the base itself).
    origins: Mapping[str, str]
    variable: str


class PrivateRoute:
    _state = threading.local()

    @classmethod
    def current(cls) -> Route | None:
        return getattr(cls._state, "route", None)

    @classmethod
    @contextmanager
    def use(cls, route: Route) -> Iterator[None]:
        previous = cls.current()
        cls._state.route = route
        try:
            yield
        finally:
            cls._state.route = previous

    @staticmethod
    def clean(rest: str) -> bool:
        """Whether a path (and query) stays where it says: no dot segment, empty segment, backslash or control
        character, after one level of percent-decoding. A `%` left after that (a double-encoded dot) is refused: a
        package name or version never carries one. A segment is judged without its path parameters (`..;x` is `..` to
        a server that strips them)."""
        path = rest.partition("?")[0]
        decoded = urllib.parse.unquote(path)
        if (
            "%" in decoded
            or "\\" in decoded
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in rest + decoded)
        ):
            return False
        segments = decoded.split("/")
        if segments and segments[0] == "":
            segments = segments[1:]
        if segments and segments[-1] == "":
            segments = segments[:-1]
        return all(s.partition(";")[0] not in ("", ".", "..") for s in segments)

    @classmethod
    def apply(cls, url: str) -> tuple[str, dict[str, str]]:
        """The address to ask and the headers to add: unchanged and none when no route is set."""
        from cordon_scanner.intel.registries.registry_request import RegistryError

        route = cls.current()
        if route is None:
            return url, {}
        parsed = urllib.parse.urlsplit(url)
        lowered = f"{parsed.scheme}://{parsed.netloc.lower()}{url[len(parsed.scheme) + 3 + len(parsed.netloc) :]}"
        for prefix, under in route.origins.items():
            if lowered == prefix or lowered.startswith((prefix + "/", prefix + "?")):
                rest = lowered[len(prefix) :]
                if not cls.clean(rest):
                    raise RegistryError(
                        f"refusing a path that leaves {route.host}'s repository ({route.variable})"
                    )
                return route.base + under + rest, {"Authorization": route.authorization}
        on_the_registry = parsed.scheme == "https" and parsed.netloc.lower() == route.host
        if on_the_registry and (url == route.base or url.startswith(route.base + "/")):
            if not cls.clean(url[len(route.base) :]):
                raise RegistryError(
                    f"refusing a path that leaves {route.host}'s repository ({route.variable})"
                )
            return url, {"Authorization": route.authorization}
        raise RegistryError(
            f"refusing to ask {parsed.netloc} about a package from {route.host}: "
            f"{route.variable} was named for {route.host} alone"
        )
