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

import re
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

    CONTENT_SIGNATURES: ClassVar[tuple[tuple[str, tuple[str, ...]], ...]] = (
        (
            "shell",
            (
                r"^\s*(?:if|elif)\s+\[\[?\s",
                r"^\s*fi\s*$",
                r"^\s*(?:then|done|esac)\s*$",
                r"^\s*for\s+\w{1,40}\s+in\s[^\n]{0,200};\s*do\b",
                r"^\s*(?:export|local|readonly)\s+\w{1,60}=",
                r"\$\(\s*[a-z][\w.-]{0,40}[\s)]",
                r"\b\w{1,40}=\$\{\w{1,40}[:}]",
                r"/dev/tcp/",
                r"^\s*(?:curl|wget|chmod|mkdir|rm|cp|mv)\s+-{1,2}\w",
                # Any file-descriptor redirection, not just `2>&1`. A reverse
                # shell one-liner ends `0>&1`, and a signature list that named
                # only the common spelling missed the line it exists for.
                r"\d>&\d",
                r">&\s*/dev/",
                r"\b(?:ba|z|k|da)?sh\s+-[ic]\b",
                r"\|\s*(?:ba|z|k|da)?sh\b",
            ),
        ),
        (
            "python",
            (
                r"^\s*(?:from\s+[\w.]{1,60}\s+)?import\s+[\w.*]{1,60}",
                r"^\s*def\s+\w{1,60}\s*\(",
                r"^\s*class\s+\w{1,60}\s*[(:]",
                r"^\s*if\s+__name__\s*==",
                r"\bself\s*\.\s*\w",
                r"^\s*(?:async\s+)?def\s",
            ),
        ),
        (
            "javascript",
            (
                r"\brequire\s*\(\s*[\"']",
                r"^\s*(?:const|let|var)\s+\w{1,60}\s*=",
                r"\bmodule\s*\.\s*exports\b",
                r"\bfunction\s*\w{0,60}\s*\([^\n)]{0,120}\)\s*\{",
                r"=>\s*\{",
                r"\bconsole\s*\.\s*log\s*\(",
            ),
        ),
    )
    """Shapes that identify a language when the filename does not.

    The gap this closes. Identification was the filename, then the shebang, and
    nothing else -- so a file with no extension and no shebang got
    `language=None` and therefore none of the language rules. A bash reverse
    shell in a file called `postinstall`, or in `payload.dat`, was completely
    invisible while the identical bytes in `postinstall.sh` were CRITICAL.
    That is a one-rename bypass of every behavioural rule the tool has, and
    `package.json` naming `"postinstall": "./postinstall"` is how it runs.

    Deliberately conservative, because a wrong answer here is worse than none:
    it points a whole language's rules at a file that is not that language.
    Two distinct markers are required (see `identify_from_content`), which is
    what separates a script from a data file that happens to contain one line
    resembling code.

    Applied ONLY where the filename said nothing. A `.md` or `.txt` is never
    re-read as shell, however much shell it contains: a README documenting
    `curl https://example.com/install.sh | bash` is documentation, that is the
    single most common shape in open-source documentation, and reading it as a
    script would report every install guide ever written.
    """

    MIN_CONTENT_MARKERS = 2
    """Distinct markers before content identification commits to a language.

    One is noise -- `2>&1` appears in a log file, `import` appears in prose
    about Python. Two of them in the same file is a shape data does not have.
    """

    MAX_SNIFF_BYTES = 8192
    """How much of the file to read for this. The head of a script says what it
    is, and an unbounded scan of every unidentified file is a cost paid on
    every scan for the rare file this exists for."""

    @classmethod
    @lru_cache(maxsize=1024)
    def _signature_patterns(cls, language: str) -> tuple[re.Pattern[str], ...]:
        for name, patterns in cls.CONTENT_SIGNATURES:
            if name == language:
                return tuple(re.compile(p, re.MULTILINE) for p in patterns)
        return ()

    @classmethod
    def identify_from_content(cls, text: str) -> str | None:
        """The language this source looks like, or None if it is not clear.

        The last resort, after the filename and the shebang. Returns None on a
        tie as well as on no evidence: two languages with equal claims means
        the evidence is weak, and guessing between them is how a YAML file gets
        read as Python.
        """
        if not text:
            return None
        head = text[: cls.MAX_SNIFF_BYTES]

        scores: list[tuple[int, str]] = []
        for language, _ in cls.CONTENT_SIGNATURES:
            hits = sum(1 for pattern in cls._signature_patterns(language) if pattern.search(head))
            if hits >= cls.MIN_CONTENT_MARKERS:
                scores.append((hits, language))

        if not scores:
            return None
        scores.sort(reverse=True)
        if len(scores) > 1 and scores[0][0] == scores[1][0]:
            return None
        return scores[0][1]

    @classmethod
    def identify(
        cls, path: str, *, shebang: str | None = None, text: str | None = None
    ) -> str | None:
        """Filename, then shebang, then shape. The whole chain, in one place.

        It existed as three call sites that each remembered a different amount
        of it, which is how the content step came to be missing from all of
        them.
        """
        by_path = cls.identify_language(path)
        if by_path is not None:
            return by_path
        by_shebang = cls.language_from_interpreter(shebang or "")
        if by_shebang is not None:
            return by_shebang
        return cls.identify_from_content(text or "")

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
