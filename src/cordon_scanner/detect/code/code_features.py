"""What the code a consumer runs says, as features the package verdict can read: its words and calls.

Family E of the detection model (`reviews/self-improving/06-DETECTION-MODEL.md`). The rules and the
capability profile name behaviours someone wrote down; most malware no rule names still reads like
malware -- the calls it makes, in the order it makes them. These features give the model the code
itself, per place (`install`, `import`, `closure`, as in `ReachedFlows`):

- `code_<place>_tok_<h>`: hashed counts of each token and each pair of tokens, the top 1,500;
- `code_<place>_api_<name>`: a call or module on a fixed list of behaviours (`exec`, `fetch`,
  `this.getCredentials`, `child_process`), by name, so a reviewer can read it;
- `code_<place>_apih_<h>`: any other member call, hashed by the member's name;
- `code_<place>_truncated`: the place held more text than is read.

A string's value is never a feature, hashed or not: every literal becomes its shape (`URL`,
`BASE64`, `HEX`, `LONG_STRING`, `STRING`). The model learns what code does, not one campaign's
addresses, and no record carries a payload. Tokens come from the scanner's own tokenizers --
`JsEval.tokens` for JavaScript, the standard library's `tokenize` for Python -- so a comment, a
template or a regular expression cannot shift where a string starts.

Deterministic (stable hashes, no clock) and bounded: at most `PLACE_BYTES` of text per place, after
the caller's per-file limits.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import re
import tokenize
from collections import Counter
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.js_eval import JsEval

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class CodeFeatures:
    """`of(reached)`: the word and call features of the files each place runs."""

    PLACES: ClassVar[tuple[str, ...]] = ("install", "import", "closure")
    HASH_MOD: ClassVar[int] = 1 << 18
    COUNT_CAP: ClassVar[int] = 20
    TOP: ClassVar[int] = 1500
    PLACE_BYTES: ClassVar[int] = 2_000_000

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
    def of(reached: Mapping[str, Sequence[tuple[str, bytes]]]) -> dict[str, float]:
        """`reached` maps a place to its files, (path, bytes), already within the per-file limits."""
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
        digest = hashlib.blake2b(text.encode("utf-8", "replace"), digest_size=4).digest()
        return int.from_bytes(digest, "big") % CodeFeatures.HASH_MOD

    @staticmethod
    def stream(path: str, text: str) -> list[tuple[str, str]]:
        """The file as (kind, token): `str` tokens keep their text only for the module check."""
        if path.lower().endswith(".py"):
            return CodeFeatures._python(text)
        try:
            tokens = JsEval.tokens(text, templates=True)
        except Exception:  # a file the tokenizer cannot read gives no features, never a failure
            return []
        out: list[tuple[str, str]] = []
        for t in tokens:
            if t.kind in ("str", "longstr", "tmpl"):
                out.append(("str", str(t.value)))
            elif t.kind == "num":
                out.append(("num", "NUM"))
            elif t.kind == "regex":
                out.append(("regex", "REGEX"))
            else:
                out.append(("name" if t.kind == "name" else "punct", str(t.value)))
        return out

    @staticmethod
    def _python(text: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        try:
            for t in tokenize.generate_tokens(io.StringIO(text).readline):
                if t.type in CodeFeatures._SKIP:
                    continue
                if t.type == tokenize.STRING:
                    out.append(("str", t.string))
                elif t.type == tokenize.NUMBER:
                    out.append(("num", "NUM"))
                elif t.type == tokenize.NAME:
                    out.append(("name", t.string))
                else:
                    out.append(("punct", t.string))
        except (tokenize.TokenError, SyntaxError, ValueError):
            return []
        return out

    @staticmethod
    def _unquoted(value: str) -> str:
        quoted = len(value) >= 2 and value[0] in "'\"`" and value[-1] == value[0]
        return value[1:-1] if quoted else value

    @staticmethod
    def _calls(place: str, walk: list[tuple[str, str]], out: Counter[str]) -> None:
        for i, (kind, value) in enumerate(walk):
            if kind == "str":
                before = walk[i - 1][1] if i >= 1 else ""
                before2 = walk[i - 2][1] if i >= 2 else ""
                if before in ("from", "import") or (
                    before == "(" and before2 in ("require", "import")
                ):
                    name = CodeFeatures._unquoted(value)
                    if name in CodeFeatures.NAMED_MODULES:
                        out[f"code_{place}_api_mod_{CodeFeatures._SAFE.sub('_', name)}"] += 1
                    elif name[:1] in "./" or CodeFeatures.shape(name) == "URL":
                        out[f"code_{place}_api_mod_path"] += 1
                    else:
                        out[f"code_{place}_api_mod_other"] += 1
            elif (
                kind == "name"
                and i + 2 < len(walk)
                and walk[i + 1][1] == "."
                and walk[i + 2][0] == "name"
            ):
                member = walk[i + 2][1]
                chain = f"{value}.{member}"
                if chain in CodeFeatures.NAMED_API:
                    out[f"code_{place}_api_{CodeFeatures._SAFE.sub('_', chain)}"] += 1
                elif member in CodeFeatures.NAMED_API:
                    out[f"code_{place}_api_{CodeFeatures._SAFE.sub('_', member)}"] += 1
                else:
                    out[f"code_{place}_apih_{CodeFeatures.hashed('m:' + member)}"] += 1

    @staticmethod
    def _place(place: str, files: Sequence[tuple[str, bytes]], out: Counter[str]) -> None:
        words: list[str] = []
        budget = CodeFeatures.PLACE_BYTES
        truncated = False
        for path, data in files:
            if budget <= 0:
                truncated = True
                break
            whole = data.decode("latin-1")
            text = whole[:budget]
            truncated = truncated or len(text) < len(whole)
            budget -= len(text)
            walk = CodeFeatures.stream(path, text)
            CodeFeatures._calls(place, walk, out)
            words.extend(CodeFeatures.shape(v) if k == "str" else v for k, v in walk)
        if truncated:
            out[f"code_{place}_truncated"] = 1
        grams: Counter[str] = Counter()
        for w in words:
            grams[f"code_{place}_tok_{CodeFeatures.hashed('1|' + w)}"] += 1
        for a, b in itertools.pairwise(words):
            grams[f"code_{place}_tok_{CodeFeatures.hashed('2|' + a + '|' + b)}"] += 1
        for key, n in sorted(grams.items(), key=lambda kv: (-kv[1], kv[0]))[: CodeFeatures.TOP]:
            out[key] = min(n, CodeFeatures.COUNT_CAP)


__all__ = ["CodeFeatures"]
