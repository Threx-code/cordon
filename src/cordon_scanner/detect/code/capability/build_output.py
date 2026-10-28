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
    """Extensions where a thousand characters on one line means a bundler ran.

    The ceiling above exists for one reason, stated in `MINIFIED_LINE`: a minified
    bundle contains a decoder beside an evaluator because that is what a module
    loader is. That is a fact about **bundlers**, and bundlers are a JavaScript and
    CSS practice. Nothing in the Python, Ruby, shell, Go or Rust toolchains emits a
    thousand-character line, so in those languages the same measurement means the
    opposite thing -- somebody obfuscated the file by hand.

    Measured, and it is how this was found. `bettercolor` is a real malicious PyPI
    package whose payload is a pyobfuscate blob in a library module: a 12KB `.py`
    file with a 6,307-character line. It matched `_is_minified`, so the ceiling took
    `SUSPECT.DECODE_CHAIN.001` from critical to medium and a CI gate would have
    passed it. Eleven of 201 sampled malicious packages were held below the gate,
    most of them this way.

    A noise ceiling that fires on obfuscated malware is worse than no ceiling: it
    turns a finding a reader would act on into one they will not see."""

    MINIFIED_MEAN_LINE = 200
    """Mean bytes per line before a file is build output rather than source.

    The third half of this test, added after the other two were not enough. A
    minifier's whole purpose is to delete newlines, so its output is one line,
    or three, and the mean line length is most of the file. Hand-written source
    averages nearer forty bytes a line however long its longest line is.

    Without this, one long line anywhere in a `.js` file made the whole file
    "minified output". `budi-kue16-riris` is a registry-spam worm -- generate a
    name, rewrite `package.json`, `exec('npm publish')`, repeat -- and it opens
    with two long array literals of Indonesian names and foods to generate the
    names from. Those two lines bought the entire file a ceiling, and
    `SUSPECT.REGISTRY.SELF_PUBLISH.001` came out at MEDIUM instead of HIGH.
    About thirty packages of that family are in the npm corpus and every one of
    them was under the gate for the same reason.

    The fifth time in this release a ceiling meant for noise was found holding
    malware below the line, and the second time for this particular ceiling."""

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
