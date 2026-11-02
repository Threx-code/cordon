"""Work done once per process: loading a bundled catalogue, compiling its rules.

A loader decorated with `OneOff.cache` is cached like `functools.cache`, cleared with
`cache_clear`. It once also recorded the time its first call took, so a file's time budget could
leave out the cost of a load that file happened to need first. No time budget cuts a file now
(2026-10-31: a scan's answer must not depend on how loaded the machine is), so nothing is timed.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, Generic, ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


class OneOff:
    @staticmethod
    def cache(loader: Callable[P, R]) -> Loader[P, R]:
        """`functools.cache` for a once-per-process load."""
        return Loader(loader)


class Loader(Generic[P, R]):
    """A cached loader (`OneOff.cache`): called like the function, cleared like `functools.cache`."""

    def __init__(self, loader: Callable[P, R]) -> None:
        self._cached: Any = functools.cache(loader)
        functools.update_wrapper(self, loader)

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R:
        result: R = self._cached(*args, **kwargs)
        return result

    def cache_clear(self) -> None:
        self._cached.cache_clear()

    def cache_info(self) -> Any:
        return self._cached.cache_info()


__all__ = ["Loader", "OneOff"]
