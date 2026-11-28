"""What the engine uses of this layer, as protocols.

`registry` hands the engine each implementation typed by one of these, and the type checker proves
the implementation conforms, so the engine never sees a concrete adapter type.
"""

from __future__ import annotations

from typing import Protocol


class ImageName(Protocol):
    """What the engine uses of an `ImageReference` parsed from a name."""

    @property
    def digest(self) -> str | None: ...
    @property
    def familiar(self) -> str: ...
    @property
    def registry(self) -> str | None: ...
    @property
    def tag(self) -> str | None: ...


class ImageReferences(Protocol):
    """What the engine uses of the class `ImageReference`."""

    def parse(self, text: str) -> ImageName | None: ...


__all__ = ["ImageName", "ImageReferences"]
