"""Answer questions and gate explicit reads of approved documents."""

from dataclasses import dataclass
from pathlib import Path

from . import defenses, rag


@dataclass(frozen=True)
class Answer:
    text: str
    source: str | None = None


class HardenedChatbot:
    def __init__(self, corpus_dir: Path = rag.CORPUS_DIR) -> None:
        self._docs = {
            doc.name: rag.Doc(doc.name, defenses.sanitize_context(doc.text))
            for doc in rag.load_corpus(corpus_dir)
        }

    def ask(self, question: str) -> Answer:
        if defenses.matches_input_rule(question):
            return Answer("The input rules flagged this question.")

        passage = rag.retrieve(question, self._docs.values())
        if passage is None:
            return Answer("I couldn't find an answer in the support documents.")

        text, withheld = defenses.filter_output(passage.text)
        return Answer(text, None if withheld else passage.name)

    def read_document(self, filename: str, *, confirmed: bool = False) -> str:
        """Return the filtered content of an explicitly approved corpus entry."""
        if not isinstance(filename, str) or filename not in self._docs:
            raise PermissionError("Choose a filename from the approved corpus.")
        if confirmed is not True:
            raise PermissionError("Confirm the document read to continue.")

        text, _ = defenses.filter_output(self._docs[filename].text)
        return text
