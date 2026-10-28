"""Whether a file is build output: compiled, bundled or minified code rather than code somebody wrote.

A bundle carries every library it was built from, so a capability hit in one says less about the
package's own intent than the same hit in its source. The capability detector asks this by the path
alone (a dist/out/build directory, a .min or .bundle name) and by the content (lines too long to have
been written by hand)."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class BuildOutput:
    """Questions about whether a file is generated build output."""

    #: A line this long means the file was generated, whatever it is called.
    #:
    #: The path globs catch `*.min.js`, `dist/` and `.yarn/releases/`, and they cannot
    #: catch a bundler that names its output with a content hash:
    #: `assets/ToolsPage-COpoWLDm.js` and `assets/index-BTLZFAP9.js` are Vite output and
    #: match no convention a glob can express. A minified bundle contains a decoder
    #: beside an evaluator because that is what a module loader is, so it supplies
    #: `SUSPECT.DECODE_CHAIN.001` and `SUSPECT.DECODE_EXEC.001` by construction.
    #:
    #: Content rather than name is also the harder signal to dodge, which is why the
    #: threshold is generous: a thousand characters on one line is not something
    #: anybody writes by hand, and hand-written code that does is already reported by
    #: `SUSPECT.OBFUSCATION.LONGLINE.001` on its own merits.
    MINIFIED_LINE = 1000

    BUNDLED_SUFFIXES = frozenset(
        {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".less", ".map"}
    )

    MINIFIED_MEAN_LINE = 200

    @staticmethod
    def is_minified(content: FileContent) -> bool:
        """Whether this file looks like build output regardless of its name.

        Long lines, an extension a bundler writes, AND long lines being what the
        file is mostly made of. See `BUNDLED_SUFFIXES` for why the second is not
        optional and `MINIFIED_MEAN_LINE` for why the third is not either.
        """
        if content.longest_line <= BuildOutput.MINIFIED_LINE:
            return False
        suffix = PurePosixPath(content.path).suffix.lower()
        if suffix not in BuildOutput.BUNDLED_SUFFIXES:
            return False
        lines = max(1, len(content.line_starts))
        return len(content.raw) / lines > BuildOutput.MINIFIED_MEAN_LINE

    @staticmethod
    def bundled(content: FileContent) -> bool:
        """Compiled or bundled output: a dist/out/build directory, a .min/.bundle file, or a file
        too large to be a hand-written script."""
        return BuildOutput.bundled_path(content.path) or len(content.raw) > 100_000

    @staticmethod
    def bundled_path(path: str) -> bool:
        """`_bundled` by the path alone: a dist/out/build directory or a .min/.bundle file."""
        member = path.rpartition("!")[2]
        return bool(
            re.search(
                r"(?:^|/)(?:dist|out|build|bundle|webpack)/|\.(?:min|bundle)\.[cm]?js$", member
            )
        )


__all__ = ["BuildOutput"]
