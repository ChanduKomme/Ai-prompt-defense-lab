"""BM25 retrieval over the knowledge base, with source citations.

Author: Chandu Komme

Documents are Markdown files. Each paragraph line is a passage. Scoring uses
Okapi BM25 (k1 = 1.4, b = 0.75) over lightly stemmed tokens, and a passage
must reach ``MIN_SCORE`` to count as an answer, so off-topic questions get
an honest "not found" instead of a weak guess.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
from pathlib import Path
import re

__author__ = "Chandu Komme"

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CORPUS_DIR = DATA_DIR / "corpus"
POISONED_DIR = DATA_DIR / "poisoned"
MIN_SCORE = 2.0
K1, B = 1.4, 0.75

_TOKEN = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset("""
a an and are as at be by can do does for from has have how i if in is it its my of on or our so
than that the their them then there these this to was we what when where which who why will with
you your can't don't it's me about into any all also just should would could please
""".split())


# Query expansion: customer words mapped to the words help articles use.
# Expanded terms count at half weight so exact matches still win.
SYNONYMS = {
    "card": ("payment",), "money": ("refund",), "package": ("parcel",), "parcel": ("package",),
    "login": ("sign",), "log": ("sign",), "2fa": ("two", "step"), "deliver": ("ship",), "ship": ("delivery",),
    "cost": ("price", "charge"), "price": ("cost",), "point": ("reward",), "guarantee": ("warranty",),
}
EXPANSION_WEIGHT = 0.5


@dataclass(frozen=True)
class Document:
    name: str
    text: str
    trusted: bool = True


@dataclass(frozen=True)
class Passage:
    """The best-matching line (``text``) plus the document body it came from (``context``).

    A real RAG pipeline hands the model whole chunks, so injected instructions
    travel with the matched text. Defenses must therefore inspect ``context``.
    """
    source: str
    text: str
    score: float
    trusted: bool = True
    context: str = ""


def stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)]
    return word


def tokenize(text: str) -> list[str]:
    return [stem(w) for w in _TOKEN.findall(text.lower()) if w not in STOPWORDS and len(w) > 1]


def load_documents(directory: Path = CORPUS_DIR, trusted: bool = True) -> list[Document]:
    return [Document(p.name, p.read_text(encoding="utf-8"), trusted) for p in sorted(directory.glob("*.md"))]


def passages(document: Document) -> list[str]:
    lines = [line.strip() for line in document.text.splitlines()]
    return [line for line in lines if line and not line.startswith("# ")]


class Index:
    def __init__(self, documents: list[Document]):
        self.documents = {d.name: d for d in documents}
        self.entries: list[tuple[Document, str, Counter]] = []
        for document in documents:
            for text in passages(document):
                self.entries.append((document, text, Counter(tokenize(text))))
        self.avg_len = (sum(sum(c.values()) for *_, c in self.entries) / len(self.entries)) if self.entries else 1.0
        df: Counter = Counter()
        for *_, counts in self.entries:
            df.update(counts.keys())
        n = len(self.entries)
        self.idf = {term: math.log(1 + (n - f + 0.5) / (f + 0.5)) for term, f in df.items()}

    def query_terms(self, query: str) -> dict[str, float]:
        weights = {term: 1.0 for term in tokenize(query)}
        for term in list(weights):
            for extra in SYNONYMS.get(term, ()):
                weights.setdefault(stem(extra), EXPANSION_WEIGHT)
        return weights

    def search(self, query: str, k: int = 2) -> list[Passage]:
        terms = self.query_terms(query)
        scored = []
        for document, text, counts in self.entries:
            length = sum(counts.values())
            score = 0.0
            for term, weight in terms.items():
                tf = counts.get(term, 0)
                if tf:
                    score += weight * self.idf[term] * tf * (K1 + 1) / (tf + K1 * (1 - B + B * length / self.avg_len))
            if score >= MIN_SCORE:
                body = "\n".join(passages(document))
                scored.append(Passage(document.name, text, round(score, 3), document.trusted, body))
        scored.sort(key=lambda p: -p.score)
        return scored[:k]
