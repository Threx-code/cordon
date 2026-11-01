"""The learned code model (release item 47): what the reached code itself looks like, as evidence
independent of the rules (notes/47-learned-code-model.md, its integration and review changes).

The verdict model reads the rules' findings, so it can only re-weigh what a rule already saw (item 46:
120 of 131 benign solo blocks over its line fall under it without their own rule). This model reads
the reached JavaScript files themselves:

```
  reached JS file ──► JsEval tokens ──► normalised (identifiers ID except a platform vocabulary,
                                         literals as classes, comments gone)
                         ├─► winnowed 5-gram shingles ─┐ blake2b buckets, two spaces:
                         └─► platform-name n-grams ────┘ [0, 2^18) shingles, [2^18, 2^19) n-grams
                                                         │
                              file score = sigmoid(bias + sum of w[bucket])   (CodeModelScores, in a worker)
                                                         │
                        package score = max over reached files      (the package step, the parent)
```

Weights ship as data (`code_model.json.gz` beside the verdict model) and are loaded per engine; a
build without the file is silent, a damaged or mismatched one is OPERATIONAL.CODE_MODEL.UNAVAILABLE.
The per-file score crosses from the worker as an internal record (`FileScoreRecord`), versioned, that
the package step (`decide/code_model.py`) consumes and the result assembly strips (outer-layer review,
option A). Here: the features, the weights and the record, which the detector and the step share.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Final

from cordon_scanner.foundation.paths import PackagePaths

WEIGHTS_PATH: Final = PackagePaths.data("detect") / "code_model.json.gz"


class CodeModelUnavailable(Exception):
    """The weights file is there but cannot be used: damaged, or made for other features."""


class CodeFeatures:
    """A file's buckets, exactly as the offline extraction made them for training."""

    VERSION: ClassVar[str] = "cf1"
    BUCKETS: ClassVar[int] = 1 << 18
    K: ClassVar[int] = 5
    WINDOW: ClassVar[int] = 4
    MAX_TOKENS: ClassVar[int] = 400_000
    PLATFORM: ClassVar[frozenset[str]] = frozenset(
        [
            "require",
            "import",
            "export",
            "module",
            "exports",
            "process",
            "env",
            "argv",
            "child_process",
            "exec",
            "execSync",
            "spawn",
            "spawnSync",
            "execFile",
            "fork",
            "eval",
            "Function",
            "Buffer",
            "from",
            "toString",
            "fs",
            "readFileSync",
            "writeFileSync",
            "readFile",
            "writeFile",
            "appendFileSync",
            "unlinkSync",
            "mkdirSync",
            "existsSync",
            "os",
            "homedir",
            "hostname",
            "userInfo",
            "platform",
            "networkInterfaces",
            "tmpdir",
            "net",
            "Socket",
            "connect",
            "createConnection",
            "http",
            "https",
            "request",
            "get",
            "post",
            "dns",
            "lookup",
            "resolve",
            "crypto",
            "createCipheriv",
            "createDecipheriv",
            "createHash",
            "fetch",
            "atob",
            "btoa",
            "XMLHttpRequest",
            "WebSocket",
            "axios",
            "setTimeout",
            "setInterval",
            "vm",
            "runInNewContext",
            "runInThisContext",
            "Script",
            "global",
            "globalThis",
            "window",
            "document",
            "cookie",
            "localStorage",
            "navigator",
            "chmodSync",
            "base64",
            "hex",
            "utf8",
            "binary",
            "zlib",
            "gunzipSync",
            "inflateSync",
            "unzipSync",
            "path",
            "join",
            "__dirname",
            "__filename",
            "JSON",
            "parse",
            "stringify",
            "fromCharCode",
            "charCodeAt",
            "split",
            "reverse",
            "replace",
            "decodeURIComponent",
        ]
    )
    KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        [
            "var",
            "let",
            "const",
            "function",
            "return",
            "if",
            "else",
            "for",
            "while",
            "do",
            "switch",
            "case",
            "break",
            "continue",
            "new",
            "try",
            "catch",
            "finally",
            "throw",
            "typeof",
            "instanceof",
            "in",
            "of",
            "class",
            "extends",
            "super",
            "this",
            "null",
            "undefined",
            "true",
            "false",
            "async",
            "await",
            "yield",
            "delete",
            "void",
            "default",
        ]
    )
    _URL: ClassVar[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9+.-]{1,10}://", re.I)
    _IP: ClassVar[re.Pattern[str]] = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
    _B64: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")
    _HEX: ClassVar[re.Pattern[str]] = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")

    @classmethod
    def vocabulary_hash(cls) -> str:
        """What the weights were made for: the parameters and both vocabularies."""
        spec = json.dumps(
            [
                cls.VERSION,
                cls.BUCKETS,
                cls.K,
                cls.WINDOW,
                sorted(cls.PLATFORM),
                sorted(cls.KEYWORDS),
            ]
        )
        return hashlib.sha256(spec.encode()).hexdigest()[:16]

    @classmethod
    def literal_class(cls, value: str) -> str:
        if cls._URL.match(value):
            return "S:URL"
        if cls._IP.match(value):
            return "S:IP"
        if "/" in value or "\\" in value:
            return "S:PATH"
        if cls._HEX.match(value):
            return "S:HEX"
        if cls._B64.match(value):
            return "S:B64"
        return "S:SHORT" if len(value) <= 16 else "S:LONG"

    @classmethod
    def tokens(cls, text: str) -> list[str]:
        from cordon_scanner.analysis.javascript.js_eval import JsEval

        out: list[str] = []
        for tok in JsEval.tokens(text, templates=True)[: cls.MAX_TOKENS]:
            kind, value = tok.kind, str(tok.value)
            if kind == "str":
                out.append("S:" + value if value in cls.PLATFORM else cls.literal_class(value))
            elif kind == "num":
                out.append("N")
            elif kind == "name":
                out.append(value if value in cls.PLATFORM or value in cls.KEYWORDS else "ID")
            else:
                out.append(value)
        return out

    @staticmethod
    def _hash(text: str) -> int:
        return int.from_bytes(hashlib.blake2b(text.encode(), digest_size=8).digest(), "big")

    @classmethod
    def buckets(cls, text: str) -> set[int]:
        """The file's shingle and platform n-gram buckets."""
        tokens = cls.tokens(text)
        hashes = [
            cls._hash("\x1f".join(tokens[i : i + cls.K]))
            for i in range(max(0, len(tokens) - cls.K + 1))
        ]
        out: set[int] = set()
        for i in range(max(1, len(hashes) - cls.WINDOW + 1)):
            window = hashes[i : i + cls.WINDOW]
            if window:
                out.add(min(window) % cls.BUCKETS)
        sequence = [t for t in tokens if t in cls.PLATFORM]
        for n in (2, 3):
            for i in range(len(sequence) - n + 1):
                gram = "A\x1f" + "\x1f".join(sequence[i : i + n])
                out.add(cls.BUCKETS + cls._hash(gram) % cls.BUCKETS)
        return out

    @classmethod
    def ngrams(cls, text: str) -> dict[int, str]:
        """The platform n-grams of a file by bucket, to name what carried a score."""
        tokens = cls.tokens(text)
        sequence = [t for t in tokens if t in cls.PLATFORM]
        out: dict[int, str] = {}
        for n in (2, 3):
            for i in range(len(sequence) - n + 1):
                gram = sequence[i : i + n]
                out[cls.BUCKETS + cls._hash("A\x1f" + "\x1f".join(gram)) % cls.BUCKETS] = ">".join(
                    gram
                )
        return out


@dataclass(frozen=True)
class CodeModelWeights:
    """A trained model: its bias and non-zero bucket weights, for the features it was made with."""

    FORMAT: ClassVar[int] = 1

    bias: float
    weights: dict[int, float]
    trained: str

    @classmethod
    def load(cls, path: Path = WEIGHTS_PATH) -> CodeModelWeights | None:
        """The shipped weights, read fresh (no module or class cache: per engine, the outer-layer
        review). None when the file is absent, so a build without the model says nothing."""
        if not path.exists():
            return None
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                data: dict[str, Any] = json.load(fh)
        except (OSError, ValueError) as error:
            raise CodeModelUnavailable(
                f"the code model's weights could not be read: {error}"
            ) from error
        if (
            data.get("format") != cls.FORMAT
            or data.get("features") != CodeFeatures.vocabulary_hash()
        ):
            raise CodeModelUnavailable(
                "the code model's weights were made for other features "
                f"(format {data.get('format')!r}, features {data.get('features')!r})"
            )
        try:
            weights = {int(k): float(v) for k, v in data["weights"].items()}
            return cls(
                bias=float(data["bias"]), weights=weights, trained=str(data.get("trained", ""))
            )
        except (KeyError, TypeError, ValueError) as error:
            raise CodeModelUnavailable(f"the code model's weights are damaged: {error}") from error

    def score(self, buckets: set[int]) -> float:
        z = self.bias + sum(self.weights.get(b, 0.0) for b in buckets)
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def carriers(self, buckets: set[int], names: dict[int, str], top: int = 3) -> list[str]:
        """The platform n-grams that raised the score most, by name."""
        weighted = sorted(
            ((self.weights.get(b, 0.0), names[b]) for b in buckets if b in names), reverse=True
        )
        return [name for weight, name in weighted[:top] if weight > 0]


class FileScoreRecord:
    """The per-file score as it crosses from a worker to the parent: the message of an internal,
    info, operational record that the package step consumes and the result assembly strips.
    Versioned; an unknown version is refused, never misparsed."""

    RULE: ClassVar[str] = "INTERNAL.CODE_MODEL.FILE_SCORE"
    VERSION: ClassVar[str] = "v1"
    _FORM: ClassVar[re.Pattern[str]] = re.compile(r"^v1 score=(\d\.\d{4}) ngrams=([^\s]*)$")
    #: The longest record the encoder writes (three carriers, each a short n-gram name) is far under
    #: this; a longer message, or more carriers, is refused before it is matched (outer-layer review).
    MAX_MESSAGE: ClassVar[int] = 512
    MAX_CARRIERS: ClassVar[int] = 3

    @classmethod
    def encode(cls, score: float, carriers: list[str]) -> str:
        names = "|".join(c.replace("|", "")[:96] for c in carriers[: cls.MAX_CARRIERS])
        return f"{cls.VERSION} score={min(max(score, 0.0), 1.0):.4f} ngrams={names}"

    @classmethod
    def current(cls, findings: Any) -> tuple[Any, ...]:
        """`findings` without a record of any other version: the cache's read path, so a result an
        older build cached is never read by a newer scorer (outer-layer review, condition 1)."""
        return tuple(
            f for f in findings if f.rule_id != cls.RULE or cls.decode(f.message) is not None
        )

    @classmethod
    def decode(cls, message: str) -> tuple[float, list[str]] | None:
        if not isinstance(message, str) or len(message) > cls.MAX_MESSAGE:
            return None
        match = cls._FORM.match(message)
        if match is None:
            return None
        names = match.group(2).split("|") if match.group(2) else []
        if len(names) > cls.MAX_CARRIERS or float(match.group(1)) > 1.0:
            return None
        return float(match.group(1)), names


__all__ = ["CodeFeatures", "CodeModelUnavailable", "CodeModelWeights", "FileScoreRecord"]
