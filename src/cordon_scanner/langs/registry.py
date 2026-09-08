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
        name = path.rpartition("/")[2]

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
        """Map a shebang interpreter to a language."""
        name = interpreter.rpartition("/")[2].split()[0] if interpreter else ""
        # `#!/usr/bin/env python3` names env, not the interpreter. The real one
        # is the argument, and this form is more common than a direct path.
        if name == "env":
            parts = interpreter.split()
            name = parts[-1].rpartition("/")[2] if len(parts) > 1 else ""
        return cls.INTERPRETERS.get(name)


__all__ = ["LanguageRegistry"]
