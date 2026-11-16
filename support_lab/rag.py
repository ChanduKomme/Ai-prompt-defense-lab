"""Rank passages from the bundled corpus by keyword overlap."""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parents[1] / "data" / "corpus"
CORPUS_FILENAMES = (
    "01-shipping-policy.txt",
    "02-account-faq.txt",
    "03-product-info.txt",
)

_WORDS = re.compile(r"[a-z0-9]+")
_SENTENCES = re.compile(r"(?<=[.!?])\s+")
_STOP = {
    "the", "and", "for", "with", "your", "you", "how", "not", "this", "that",
    "can", "will", "from", "was", "were", "has", "have", "what", "where",
    "when", "which", "who", "does", "why", "much", "many", "about",
}


@dataclass(frozen=True)
class Doc:
    name: str
    text: str


def load_corpus(corpus_dir: Path = CORPUS_DIR) -> list[Doc]:
    """Load the approved filenames from a directory chosen at startup."""
    return [
        Doc(name, (corpus_dir / name).read_text(encoding="utf-8"))
        for name in CORPUS_FILENAMES
    ]


def _tokens(text: str) -> set[str]:
    return {word for word in _WORDS.findall(text.lower()) if len(word) > 2 and word not in _STOP}


def retrieve(query: str, docs: Iterable[Doc]) -> Doc | None:
    """Return the best passage when at least two distinct terms match."""
    query_terms = _tokens(query)
    best = None
    best_score = 1

    for doc in docs:
        for passage in _SENTENCES.split(" ".join(doc.text.split())):
            score = len(query_terms & _tokens(passage))
            if score > best_score:
                best = Doc(doc.name, passage)
                best_score = score

    return best
