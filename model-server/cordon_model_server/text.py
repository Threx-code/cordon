"""Cordon's judge model over agent text: the vectoriser and scorer, shared by training and serving.

A passage (a paragraph of an instruction file, a skill, a tool description) becomes hashed character
3-5-grams and word 1-2-grams, weighted by inverse document frequency and normalised; a logistic
model scores it, and a second one names the attack's category. A file's score is its worst
passage's, and that passage, quoted exactly from the text, is the evidence.

Everything a model needs is plain arrays (`numpy.save`, read back with `allow_pickle=False`) and a
few numbers in the signed manifest: loading a bundle never unpickles anything. The hashing is
scikit-learn's, at the version both images pin, so a passage is vectorised the same way in
training and in serving.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer

CHAR_FEATURES: Final = 1 << 20
WORD_FEATURES: Final = 1 << 18
MAX_PASSAGE: Final = 1200
_HIDDEN: Final = re.compile(
    "[" + "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)) + "]"
)
_PARAGRAPH: Final = re.compile(r"\n\s*\n")


class TextVectoriser:
    def __init__(self, idf: np.ndarray | None = None) -> None:
        self.char = HashingVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            n_features=CHAR_FEATURES,
            alternate_sign=False,
            norm=None,
        )
        self.word = HashingVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            n_features=WORD_FEATURES,
            alternate_sign=False,
            norm=None,
            token_pattern=r"(?u)\b\w[\w.\-/]{1,40}\b",  # noqa: S106 - a word pattern, not a secret
        )
        self.idf = idf

    @staticmethod
    def normalise(text: str) -> str:
        """NFKC, invisible characters removed, lower case, whitespace collapsed: what an attacker
        varies to slip past a pattern is not what the model reads."""
        text = unicodedata.normalize("NFKC", text)
        text = _HIDDEN.sub("", text).lower()
        return re.sub(r"\s+", " ", text).strip()[:MAX_PASSAGE]

    def counts(self, texts: list[str]) -> sparse.csr_matrix:
        normalised = [self.normalise(t) for t in texts]
        return sparse.hstack(
            [self.char.transform(normalised), self.word.transform(normalised)]
        ).tocsr()

    def fit_idf(self, texts: list[str]) -> None:
        counts = self.counts(texts)
        document_frequency = np.bincount(counts.indices, minlength=counts.shape[1]).astype(
            np.float64
        )
        self.idf = (np.log((1 + counts.shape[0]) / (1 + document_frequency)) + 1.0).astype(
            np.float32
        )

    def transform(self, texts: list[str]) -> sparse.csr_matrix:
        if self.idf is None:
            raise ValueError("the vectoriser has no idf: fit or load it first")
        weighted = self.counts(texts).multiply(self.idf).tocsr()
        norms = np.sqrt(np.asarray(weighted.multiply(weighted).sum(axis=1)).ravel())
        norms[norms == 0] = 1.0
        return sparse.diags(1.0 / norms) @ weighted

    @staticmethod
    def passages(text: str) -> list[str]:
        """Paragraphs, each cut to a bounded passage, as written (unnormalised): what is quoted."""
        out = []
        for block in _PARAGRAPH.split(text):
            block = block.strip()
            if len(block) >= 12:
                out.extend(
                    block[start : start + MAX_PASSAGE]
                    for start in range(0, len(block), MAX_PASSAGE)
                )
        return out


@dataclass
class TextModel:
    vectoriser: TextVectoriser
    weights: np.ndarray
    bias: float
    category_weights: np.ndarray
    category_bias: np.ndarray
    categories: tuple[str, ...]

    FILES: Final = (
        "text_idf.npy",
        "text_weights.npy",
        "text_bias.npy",
        "text_category_weights.npy",
        "text_category_bias.npy",
    )

    def scores(self, passages: list[str]) -> np.ndarray:
        if not passages:
            return np.zeros(0)
        logits = self.vectoriser.transform(passages) @ self.weights + self.bias
        return 1.0 / (1.0 + np.exp(-np.asarray(logits).ravel()))

    def category(self, passage: str) -> str:
        logits = self.vectoriser.transform([passage]) @ self.category_weights.T + self.category_bias
        return self.categories[int(np.argmax(np.asarray(logits).ravel()))]

    def save(self, root: Path) -> None:
        np.save(root / "text_idf.npy", self.vectoriser.idf)
        np.save(root / "text_weights.npy", self.weights.astype(np.float32))
        np.save(root / "text_bias.npy", np.array([self.bias], dtype=np.float32))
        np.save(root / "text_category_weights.npy", self.category_weights.astype(np.float32))
        np.save(root / "text_category_bias.npy", self.category_bias.astype(np.float32))

    @staticmethod
    def load(root: Path, categories: tuple[str, ...]) -> TextModel:
        def read(name: str) -> np.ndarray:
            return np.load(root / name, allow_pickle=False)

        weights = read("text_weights.npy")
        idf = read("text_idf.npy")
        category_weights = read("text_category_weights.npy")
        if idf.shape != (CHAR_FEATURES + WORD_FEATURES,) or weights.shape != idf.shape:
            raise ValueError("the text model's arrays do not match this vectoriser")
        if category_weights.shape != (len(categories), idf.shape[0]):
            raise ValueError("the category model does not match its category list")
        return TextModel(
            TextVectoriser(idf),
            weights,
            float(read("text_bias.npy")[0]),
            category_weights,
            read("text_category_bias.npy"),
            categories,
        )
