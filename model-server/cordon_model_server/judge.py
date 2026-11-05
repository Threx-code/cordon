"""`POST /v1/judge`: the cordon.judge/v1 contract, answered by Cordon's text model.

The same request the scanner's `--judge cordon-cloud` sends (schemas/cordon-judge-v1.schema.json):
one piece of agent-facing text, its kind and its path. The text's worst passage decides the verdict
against the bundle's thresholds, and that passage -- cut from the text as written, so it is an exact
quote -- is the evidence; the category comes from the model's second head. No language model, no
prompt for the text to steer: a passage that says "ignore your instructions" is scored, never obeyed.
"""

from __future__ import annotations

import re
from typing import Any, Final

from cordon_model_server.scoring import RequestError
from cordon_model_server.text import MAX_PASSAGE, TextModel

KINDS: Final = frozenset({"agent instruction file", "agent hook command", "MCP tool description"})
MAX_TEXT: Final = 6000
MAX_EVIDENCE: Final = 300
_VERSION: Final = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class Judge:
    def __init__(self, model: TextModel, malicious: float, suspicious: float) -> None:
        self.model = model
        self.malicious = malicious
        self.suspicious = suspicious

    @staticmethod
    def parse(body: Any) -> tuple[str, str]:
        """(kind, text) of a valid request; anything else is refused with the reason."""
        if not isinstance(body, dict) or set(body) != {"prompt_version", "kind", "path", "text"}:
            raise RequestError("the request is exactly prompt_version, kind, path and text")
        version, kind, path, text = body["prompt_version"], body["kind"], body["path"], body["text"]
        if not isinstance(version, str) or not _VERSION.match(version):
            raise RequestError("prompt_version is a short version name")
        if kind not in KINDS:
            raise RequestError(f"kind is one of {sorted(KINDS)}")
        if not isinstance(path, str) or len(path) > 1000 or any(c in path for c in "\r\n\x00"):
            raise RequestError("path is one line of at most 1000 characters")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
            raise RequestError(f"text is 1 to {MAX_TEXT} characters, not all whitespace")
        return kind, text

    def verdict(self, text: str) -> dict[str, str]:
        passages = self.model.vectoriser.passages(text) or [text.strip()[:MAX_PASSAGE]]
        scores = self.model.scores(passages)
        best = int(scores.argmax())
        score = float(scores[best])
        if score <= self.suspicious:
            return {
                "verdict": "benign",
                "category": "other",
                "evidence": "",
                "reason": "No passage reads as an attack.",
            }
        evidence = passages[best][:MAX_EVIDENCE]
        category = self.model.category(passages[best])
        level = "malicious" if score > self.malicious else "suspicious"
        return {
            "verdict": level,
            "category": category,
            "evidence": evidence,
            "reason": f"Cordon's text model scores this passage {score:.2f} as {category.replace('-', ' ')}.",
        }
