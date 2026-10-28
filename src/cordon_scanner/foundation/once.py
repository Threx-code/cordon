"""Work done once per process (loading a bundled catalogue, compiling its rules), kept apart from
the time charged to the file that happened to need it first.

A file's time budget (`limits.per_file_timeout`) measures what inspecting that file costs. The first
agent configuration in a scan used to pay for compiling the whole agent threat catalogue as well:
two seconds on an idle machine, past the five-second budget on a loaded one, and a two-line
`.mcp.json` came back incomplete. A loader decorated with `OneOff.cache` is cached like
`functools.cache`, and the time its first call takes is recorded for the thread that made it, so
the budget can leave it out. Only the outermost load counts when one loader calls another.
"""

from __future__ import annotations

import functools
import threading
import time
from collections.abc import Callable
from typing import Any, ClassVar, Generic, ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


class OneOff:
    _local: ClassVar[threading.local] = threading.local()

    @staticmethod
    def cache(loader: Callable[P, R]) -> Loader[P, R]:
        """`functools.cache`, recording the time spent computing a value not yet cached."""
        return Loader(loader)

    @staticmethod
    def spent() -> float:
        """Seconds this thread has spent in one-off loads so far."""
        return float(getattr(OneOff._local, "spent", 0.0))


class Loader(Generic[P, R]):
    """A cached loader (`OneOff.cache`): called like the function, cleared like `functools.cache`."""

    def __init__(self, loader: Callable[P, R]) -> None:
        self._cached: Any = functools.cache(loader)
        functools.update_wrapper(self, loader)

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R:
        local = OneOff._local
        misses = self._cached.cache_info().misses
        depth = getattr(local, "depth", 0)
        local.depth = depth + 1
        started = time.perf_counter()
        try:
            result: R = self._cached(*args, **kwargs)
            return result
        finally:
            local.depth = depth
            if depth == 0 and self._cached.cache_info().misses != misses:
                local.spent = getattr(local, "spent", 0.0) + time.perf_counter() - started

    def cache_clear(self) -> None:
        self._cached.cache_clear()

    def cache_info(self) -> Any:
        return self._cached.cache_info()


__all__ = ["Loader", "OneOff"]
