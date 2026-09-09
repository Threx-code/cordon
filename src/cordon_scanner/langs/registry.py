"""Language identification.

Identifying a file's language decides which rules apply to it, so getting it
wrong has two costs: rules that should fire do not, and rules written for another
syntax fire on strings that happen to look similar. Both erode trust in the tool,
and the second is the faster of the two.

Identification is data, not code. Adding a language means adding entries here,
which is the same principle that governs rule packs: a new ecosystem should be a
data change, not an engine change.
"""

from __future__ import annotations

from functools import lru_cache
from typing import ClassVar

from cordon_scanner.core.paths import basename


# Extension to language. Ordered pairs rather than a mapping because some
# languages need multi-part suffixes checked before their single-part ones.
class LanguageRegistry:
    """Maps a path or a shebang to a language identifier.

    A class rather than a set of tables and lookups so that the mapping and the
    rules that read it stay together. The tables are the interesting part: a
    language identified wrongly sends a file to the wrong rule pack, and a file
    with no identified language is scanned by fewer rules than it should be.
    Both are silent losses of coverage, so the data and its interpretation are
    reviewed as one unit.

    Stateless, and the lookups are cached, so there is nothing to construct.
    """

    EXTENSIONS: tuple[tuple[str, str], ...] = (
        (".py", "python"),
        (".pyi", "python"),
        (".pyw", "python"),
        (".js", "javascript"),
        (".mjs", "javascript"),
        (".cjs", "javascript"),
        (".jsx", "javascript"),
        (".ts", "typescript"),
        (".mts", "typescript"),
        (".cts", "typescript"),
        (".tsx", "typescript"),
        (".java", "java"),
        (".kt", "kotlin"),
        (".kts", "kotlin"),
        (".go", "go"),
        (".rs", "rust"),
        (".c", "c"),
        (".h", "c"),
        (".cc", "cpp"),
        (".cpp", "cpp"),
        (".cxx", "cpp"),
        (".hpp", "cpp"),
        (".cs", "csharp"),
        (".php", "php"),
        (".rb", "ruby"),
        (".swift", "swift"),
        (".dart", "dart"),
        (".sh", "shell"),
        (".bash", "shell"),
        (".zsh", "shell"),
        (".ps1", "powershell"),
        (".psm1", "powershell"),
        (".lua", "lua"),
        (".scala", "scala"),
        (".ex", "elixir"),
        (".exs", "elixir"),
        (".hs", "haskell"),
        (".sql", "sql"),
        (".yaml", "yaml"),
        (".yml", "yaml"),
        (".json", "json"),
        (".toml", "toml"),
        (".xml", "xml"),
        (".md", "markdown"),
    )

    # Files whose name determines their language regardless of extension. These are
    # frequently the most security-relevant files in a repository, and several have
    # no extension at all.
    FILENAMES: ClassVar[dict[str, str]] = {
        "Dockerfile": "dockerfile",
        "Containerfile": "dockerfile",
        "Makefile": "makefile",
        "GNUmakefile": "makefile",
        "Jenkinsfile": "groovy",
        "Gemfile": "ruby",
        "Rakefile": "ruby",
        "Podfile": "ruby",
        "build.gradle": "groovy",
        "build.gradle.kts": "kotlin",
        "CMakeLists.txt": "cmake",
        "setup.py": "python",
        "conanfile.py": "python",
        "build.rs": "rust",
    }

    # Interpreter to language, for executable scripts with no extension. A file
    # declaring an interpreter is stating what will execute it, which is stronger
    # evidence than its name.
    INTERPRETERS: ClassVar[dict[str, str]] = {
        "python": "python",
        "python2": "python",
        "python3": "python",
        "node": "javascript",
        "deno": "javascript",
        "bun": "javascript",
        "sh": "shell",
        "bash": "shell",
        "zsh": "shell",
        "dash": "shell",
        "ksh": "shell",
        "ruby": "ruby",
        "perl": "perl",
        "php": "php",
        "pwsh": "powershell",
        "lua": "lua",
    }

    @staticmethod
    @lru_cache(maxsize=4096)
    def identify_language(path: str) -> str | None:
        """Identify a language from a path alone.

        Filename first, because a name like `Dockerfile` is decisive and several
        such files have no extension. Extension second. Content-based
        identification (shebang) needs the file's bytes and is handled where
        those are available.

        Cached because inventory and unit production both ask, and a repository
        has far fewer distinct extensions than files.
        """
        name = basename(path)

        if name in LanguageRegistry.FILENAMES:
            return LanguageRegistry.FILENAMES[name]

        # Dockerfile.dev, Dockerfile.prod and similar.
        if name.startswith(("Dockerfile.", "Containerfile.")):
            return "dockerfile"

        lowered = name.lower()
        for suffix, language in LanguageRegistry.EXTENSIONS:
            if lowered.endswith(suffix):
                return language

        return None

    @classmethod
    def language_from_interpreter(cls, interpreter: str) -> str | None:
        """Map a shebang interpreter to a language.

        Every step is guarded because the input is not always a shebang. The
        same routine reads tokens out of lifecycle commands, and a token there
        can be anything somebody wrote in a `package.json` -- `eslint src/`
        ends a token with a slash, which leaves nothing after the last one.
        `"src/".rpartition("/")[2].split()` is an empty list, and indexing it
        raised straight out of the walk: the whole scan of Next.js aborted with
        `IndexError` and reported nothing at all.

        A crash here is the most expensive failure this project has. Every
        other error path produces a finding saying what was not examined; this
        one produced no result to attach a finding to.
        """
        head = interpreter.rpartition("/")[2].split() if interpreter else []
        name = head[0] if head else ""
        # `#!/usr/bin/env python3` names env, not the interpreter. The real one
        # is the argument, and this form is more common than a direct path.
        if name == "env":
            parts = interpreter.split()
            name = parts[-1].rpartition("/")[2] if len(parts) > 1 else ""
        return cls.INTERPRETERS.get(name)


__all__ = ["LanguageRegistry"]
