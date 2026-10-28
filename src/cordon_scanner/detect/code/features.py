"""What the code a consumer runs says, as features the package verdict can read: its words and calls.

Family E of the detection model (`reviews/self-improving/06-DETECTION-MODEL.md`). The rules and the
capability profile name behaviours someone wrote down; most malware no rule names still reads like
malware -- the calls it makes, in the order it makes them. These features give the model the code
itself, per place (`install`, `import`, `closure`, as in `ReachedFlows`):

- `code_<place>_tok_<h>`: hashed counts of each token and each pair of tokens, the top 1,500;
- `code_<place>_api_<name>`: a call or module on a fixed list of behaviours (`exec`, `fetch`,
  `this.getCredentials`, `child_process`), by name, so a reviewer can read it;
- `code_<place>_apih_<h>`: any other member call, hashed by the member's name.

A string's value is never a feature, hashed or not: every literal becomes its shape (`URL`,
`BASE64`, `HEX`, `LONG_STRING`, `STRING`). The model learns what code does, not one campaign's
addresses, and no record carries a payload. Tokens come from the scanner's own tokenizers --
`JsEval.tokens` for JavaScript and TypeScript, the standard library's `tokenize` for Python -- so a
comment, a template or a regular expression cannot shift where a string starts. A shell script and
an install hook's command line (`postinstall` in a `package.json`: most install-time malware is
that one line) are split into words, and a word that is not a plain command, flag or name -- an
address, a path, a blob -- is a string, its shape.

Every byte is read: a cap on how much of a file is read is where a payload padded past it would
go. Memory is bounded instead -- a file is read a `WINDOW` at a time and only counts are held -- and
deterministic (stable hashes, no clock): a file read in windows gives the features it gives whole.
"""

from __future__ import annotations

import hashlib
import re
import tokenize
from collections import Counter
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.js_eval import JsEval

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence

    from cordon_scanner.analysis.javascript.js_eval import Tok

    #: A file's bytes, or a callable giving them in order a window at a time.
    Source = bytes | Callable[[], Iterator[bytes]]


class CodeFeatures:
    """`of(reached)`: the word and call features of the files each place runs."""

    PLACES: ClassVar[tuple[str, ...]] = ("install", "import", "closure")
    HASH_MOD: ClassVar[int] = 1 << 18
    COUNT_CAP: ClassVar[int] = 20
    TOP: ClassVar[int] = 1500
    #: A file is read a window at a time, every byte of it: no file is too large to read.
    WINDOW: ClassVar[int] = 1 << 20
    #: A window is cut after its last whole token at least this far from its end; the rest is
    #: read again with the next window.
    MARGIN: ClassVar[int] = 1 << 14
    #: A literal or comment longer than this is skipped to its end rather than carried.
    CARRY: ClassVar[int] = 4 << 20
    #: Distinct words whose hash is remembered at once.
    DIGESTS: ClassVar[int] = 200_000

    NAMED_API: ClassVar[frozenset[str]] = frozenset(
        {
            "getCredentials",
            "this.getCredentials",
            "thisArg.getCredentials",
            "helpers.request",
            "helpers.httpRequest",
            "helpers.httpRequestWithAuthentication",
            "helpers.getBinaryDataBuffer",
            "exec",
            "execSync",
            "execFile",
            "spawn",
            "spawnSync",
            "fork",
            "eval",
            "Function",
            "atob",
            "fromCharCode",
            "fetch",
            "XMLHttpRequest",
            "runInNewContext",
            "runInThisContext",
            "resolve",
            "lookup",
            "connect",
            "request",
            "writeFile",
            "writeFileSync",
            "readFile",
            "readFileSync",
            "unlink",
            "binding",
            "from",
            "networkInterfaces",
            "userInfo",
            "hostname",
            "env",
            "subtle",
            "getPassword",
            "findCredentials",
        }
    )
    NAMED_MODULES: ClassVar[frozenset[str]] = frozenset(
        {
            "child_process",
            "fs",
            "fs/promises",
            "os",
            "net",
            "dns",
            "dns/promises",
            "http",
            "https",
            "tls",
            "vm",
            "crypto",
            "zlib",
            "node-fetch",
            "axios",
            "got",
            "n8n-workflow",
            "keytar",
            "dgram",
            "cluster",
            "worker_threads",
            "inspector",
            "v8",
            "module",
            "request",
            "ws",
        }
    )

    _URL: ClassVar[re.Pattern[str]] = re.compile(
        r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z0-9.-]+\.(?:com|net|org|io|ru|xyz|top|cn|info)\b",
        re.I,
    )
    _HEX: ClassVar[re.Pattern[str]] = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|\b[0-9a-fA-F]{32,}\b")
    _BASE64: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    _SAFE: ClassVar[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_.$]")
    SHELL: ClassVar[tuple[str, ...]] = (".sh", ".bash", ".bat", ".cmd", ".ps1")
    _SHELL_TOKEN: ClassVar[re.Pattern[str]] = re.compile(
        r"""'[^']{0,1000}'|"[^"]{0,1000}"|\|\||&&|>>|[|;&<>()`{}$=]|[^\s|;&<>()`{}$='"]{1,1000}"""
    )
    _SHELL_WORD: ClassVar[re.Pattern[str]] = re.compile(
        r"[A-Za-z_][A-Za-z0-9_.-]{0,39}|-{1,2}[A-Za-z][A-Za-z0-9-]{0,30}"
    )
    _SKIP: ClassVar[frozenset[int]] = frozenset(
        {
            tokenize.COMMENT,
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.ENCODING,
            tokenize.ENDMARKER,
        }
    )

    @staticmethod
    def of(reached: Mapping[str, Sequence[tuple[str, Source]]]) -> dict[str, float]:
        """`reached` maps a place to its files: (path, bytes), or (path, a callable giving the
        file's windows in order) for a file too large to hold. Every byte is read either way."""
        out: Counter[str] = Counter()
        for place in CodeFeatures.PLACES:
            files = reached.get(place)
            if files:
                CodeFeatures._place(place, files, out)
        return {
            k: float(min(v, CodeFeatures.COUNT_CAP)) if "_api" in k else float(v)
            for k, v in out.items()
        }

    @staticmethod
    def shape(value: object) -> str:
        """What a literal looks like, never what it says."""
        s = value if isinstance(value, str) else str(value)
        if CodeFeatures._URL.search(s):
            return "URL"
        if CodeFeatures._HEX.search(s):
            return "HEX"
        if CodeFeatures._BASE64.search(s):
            return "BASE64"
        return "LONG_STRING" if len(s) > 120 else "STRING"

    @staticmethod
    def hashed(text: str) -> int:
        return CodeFeatures._digest(text) % CodeFeatures.HASH_MOD

    @staticmethod
    def _digest(text: str) -> int:
        digest = hashlib.blake2b(text.encode("utf-8", "replace"), digest_size=4).digest()
        return int.from_bytes(digest, "big")

    @staticmethod
    def windows(source: Source) -> Iterator[bytes]:
        """The file's bytes in order, a window at a time."""
        if isinstance(source, bytes):
            for start in range(0, max(len(source), 1), CodeFeatures.WINDOW):
                yield source[start : start + CodeFeatures.WINDOW]
        else:
            yield from source()

    @staticmethod
    def stream(path: str, windows: Iterable[bytes]) -> Iterator[tuple[str, str]]:
        """The file as (kind, token), window by window: a `str` token keeps its text only for the
        module check and its shape; `long` is a literal or comment past `CARRY`, skipped to its
        end -- a blob padding a file reads as one long string, never as code or as nothing."""
        texts = (window.decode("latin-1") for window in windows)
        lower = path.lower()
        if lower.endswith(".py"):
            return CodeFeatures._python(texts)
        if lower.endswith(CodeFeatures.SHELL):
            return CodeFeatures._carried(texts, CodeFeatures._shell_cut)
        return CodeFeatures._carried(texts, CodeFeatures._js_cut)

    @staticmethod
    def _carried(
        texts: Iterable[str], cut_of: Callable[[str, bool], tuple[list[tuple[str, str]], int]]
    ) -> Iterator[tuple[str, str]]:
        """Each window's tokens up to its cut (`cut_of(text, last)`); the rest is read again with
        the next window, so no token is split. When one literal or comment fills more than `CARRY`
        it is skipped to its closing delimiter instead of carried."""
        carry, until = "", ""
        texts = iter(texts)
        text_now = next(texts, None)
        while text_now is not None:
            text_next = next(texts, None)
            last = text_next is None
            text = carry + text_now
            carry, text_now = "", text_next
            if until:
                end = CodeFeatures._closing(text, until)
                if end < 0:
                    carry = "" if last else text[-CodeFeatures.MARGIN :]
                    continue
                text, until = text[end:], ""
            walk, cut = cut_of(text, last)
            yield from walk
            rest = text[cut:]
            if len(rest) > CodeFeatures.CARRY:
                opened = rest.lstrip()
                pair = next((p for p in CodeFeatures._OPEN if opened.startswith(p[0])), None)
                if pair is None:  # not a literal: read as it stands, whole
                    yield from cut_of(rest, True)[0]
                    rest = ""
                else:
                    yield ("long", "LONG_STRING")
                    body = opened[len(pair[0]) :]
                    end = CodeFeatures._closing(body, pair[1])
                    rest = body[end:] if end >= 0 else body[-CodeFeatures.MARGIN :]
                    until = pair[1] if end < 0 else ""
            carry = rest
            if last and carry:
                yield from cut_of(carry, True)[0]

    #: What opens a literal or comment, and what closes it.
    _OPEN: ClassVar[tuple[tuple[str, str], ...]] = (
        ("/*", "*/"),
        ("//", "\n"),
        ("`", "`"),
        ('"', '"'),
        ("'", "'"),
    )

    @staticmethod
    def _closing(text: str, until: str) -> int:
        """One past the first `until` in `text` not escaped by a backslash, or -1."""
        at = text.find(until)
        while at >= 0:
            back = at - 1
            while until in "`'\"" and back >= 0 and text[back] == "\\":
                back -= 1
            if (at - 1 - back) % 2 == 0:
                return at + len(until)
            at = text.find(until, at + 1)
        return -1

    @staticmethod
    def _js_cut(text: str, last: bool) -> tuple[list[tuple[str, str]], int]:
        """JavaScript and TypeScript tokens up to the end of the last whole top-level token at
        least `MARGIN` before the text's end: never inside a string, a comment or a template."""
        try:
            tokens = JsEval.tokens(text, templates=True)
        except Exception:  # a text the tokenizer cannot read gives no features, never a failure  # noqa: BLE001
            return [], len(text)
        limit = len(text) if last else len(text) - CodeFeatures.MARGIN
        keep = cut = depth = 0
        for i, t in enumerate(tokens):
            if t.end > limit:
                break
            if t.kind == "punct" and text[t.start : t.start + 1] == "`":
                depth += 1 if t.value == "(" else -1
            if depth == 0:
                keep, cut = i + 1, t.end
        if last:
            keep, cut = len(tokens), len(text)
        return [CodeFeatures._item(t) for t in tokens[:keep]], cut

    @staticmethod
    def _item(t: Tok) -> tuple[str, str]:
        if t.kind in ("str", "longstr", "tmpl"):
            return ("str", str(t.value))
        if t.kind == "num":
            return ("num", "NUM")
        if t.kind == "regex":
            return ("regex", "REGEX")
        return ("name" if t.kind == "name" else "punct", str(t.value))

    @staticmethod
    def _shell_cut(text: str, last: bool) -> tuple[list[tuple[str, str]], int]:
        cut = len(text) if last else text.rfind("\n", 0, len(text) - CodeFeatures.MARGIN) + 1
        return CodeFeatures._shell(text[:cut]), cut

    @staticmethod
    def _python(texts: Iterable[str]) -> Iterator[tuple[str, str]]:
        """Python tokens across windows: the standard tokenizer reads line by line, so the file is
        given to it a line at a time. A file it cannot finish keeps what it read."""

        def lines() -> Iterator[str]:
            rest = ""
            for text in texts:
                *whole, rest = (rest + text).split("\n")
                yield from (line + "\n" for line in whole)
                if len(rest) > CodeFeatures.CARRY:
                    yield rest
                    rest = ""
            if rest:
                yield rest

        read = lines()
        try:
            for t in tokenize.generate_tokens(lambda: next(read, "")):
                if t.type in CodeFeatures._SKIP:
                    continue
                if t.type == tokenize.STRING:
                    yield ("str", t.string)
                elif t.type == tokenize.NUMBER:
                    yield ("num", "NUM")
                elif t.type == tokenize.NAME:
                    yield ("name", t.string)
                else:
                    yield ("punct", t.string)
        except (tokenize.TokenError, SyntaxError, ValueError):
            return

    @staticmethod
    def _shell(text: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for match in CodeFeatures._SHELL_TOKEN.finditer(text):
            word = match.group()
            if word in ("||", "&&", ">>") or (len(word) == 1 and not word.isalnum()):
                out.append(("punct", word))
            elif CodeFeatures._SHELL_WORD.fullmatch(word) and CodeFeatures.shape(word) == "STRING":
                out.append(("name", word))
            else:
                out.append(("str", word))
        return out

    @staticmethod
    def _unquoted(value: str) -> str:
        quoted = len(value) >= 2 and value[0] in "'\"`" and value[-1] == value[0]
        return value[1:-1] if quoted else value

    @staticmethod
    def _call(place: str, ring: list[tuple[str, str]], out: Counter[str]) -> None:
        """The call or import at `ring[2]`, with two tokens either side of it."""
        kind, value = ring[2]
        if kind == "str":
            before, before2 = ring[1][1], ring[0][1]
            if before in ("from", "import") or (before == "(" and before2 in ("require", "import")):
                name = CodeFeatures._unquoted(value)
                if name in CodeFeatures.NAMED_MODULES:
                    out[f"code_{place}_api_mod_{CodeFeatures._SAFE.sub('_', name)}"] += 1
                elif name[:1] in "./" or CodeFeatures.shape(name) == "URL":
                    out[f"code_{place}_api_mod_path"] += 1
                else:
                    out[f"code_{place}_api_mod_other"] += 1
        elif kind == "name" and ring[3][1] == "." and ring[4][0] == "name":
            member = ring[4][1]
            chain = f"{value}.{member}"
            if chain in CodeFeatures.NAMED_API:
                out[f"code_{place}_api_{CodeFeatures._SAFE.sub('_', chain)}"] += 1
            elif member in CodeFeatures.NAMED_API:
                out[f"code_{place}_api_{CodeFeatures._SAFE.sub('_', member)}"] += 1
            else:
                out[f"code_{place}_apih_{CodeFeatures.hashed('m:' + member)}"] += 1

    @staticmethod
    def _place(place: str, files: Sequence[tuple[str, Source]], out: Counter[str]) -> None:
        """Every token of every file, counted as it is read: a token and the pair it ends, hashed
        once per distinct word. Nothing but the counts is held, whatever the files' size."""
        mod, empty = CodeFeatures.HASH_MOD, ("", "")
        grams: Counter[int] = Counter()
        digests: dict[str, int] = {}
        prev = -1
        for path, source in files:
            ring = [empty, empty]
            for kind, value in CodeFeatures.stream(path, CodeFeatures.windows(source)):
                ring.append((kind, value))
                if len(ring) == 5:
                    CodeFeatures._call(place, ring, out)
                    del ring[0]
                word = CodeFeatures.shape(value) if kind == "str" else value
                digest = digests.get(word)
                if digest is None:
                    if len(digests) >= CodeFeatures.DIGESTS:
                        digests.clear()
                    digest = digests[word] = CodeFeatures._digest("1|" + word)
                grams[digest % mod] += 1
                if prev >= 0:
                    grams[(((prev * 0x01000193) ^ digest ^ 0x5BD1E995) & 0xFFFFFFFF) % mod] += 1
                prev = digest
            ring += [empty, empty]
            while len(ring) >= 5:
                CodeFeatures._call(place, ring, out)
                del ring[0]
        for key, n in sorted(grams.items(), key=lambda kv: (-kv[1], kv[0]))[: CodeFeatures.TOP]:
            out[f"code_{place}_tok_{key}"] = min(n, CodeFeatures.COUNT_CAP)


__all__ = ["CodeFeatures"]
