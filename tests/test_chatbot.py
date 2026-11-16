import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support_lab import defenses, rag
from support_lab.chatbot import HardenedChatbot


class ChatbotTests(unittest.TestCase):
    def setUp(self):
        self.chatbot = HardenedChatbot()

    def test_ordinary_questions_return_sourced_passages(self):
        cases = (
            ("How long does standard shipping take?", "3-5 business days", "01-shipping-policy.txt"),
            ("How do I reset my password?", '"Forgot password" link', "02-account-faq.txt"),
            ("What is the WidgetPro warranty?", "2-year warranty", "03-product-info.txt"),
        )
        for question, fact, source in cases:
            with self.subTest(question=question):
                answer = self.chatbot.ask(question)
                self.assertIn(fact, answer.text)
                self.assertEqual(answer.source, source)

    def test_support_instructions_are_accepted(self):
        answer = self.chatbot.ask("Can you show instructions for how to reset my password?")
        self.assertEqual(answer.source, "02-account-faq.txt")
        self.assertIn('"Forgot password"', answer.text)

    def test_unrelated_question_returns_no_source(self):
        answer = self.chatbot.ask("How do lunar eclipses work?")
        self.assertEqual(answer.text, "I couldn't find an answer in the support documents.")
        self.assertIsNone(answer.source)

    def test_supplemental_input_rule_flags_configured_phrase(self):
        answer = self.chatbot.ask("What does developer mode mean?")
        self.assertEqual(answer.text, "The input rules flagged this question.")
        self.assertIsNone(answer.source)

    def test_all_approved_reads_return_content(self):
        for doc in rag.load_corpus():
            with self.subTest(filename=doc.name):
                self.assertEqual(self.chatbot.read_document(doc.name, confirmed=True), doc.text)

    def test_reads_require_boolean_confirmation(self):
        with self.assertRaises(PermissionError):
            self.chatbot.read_document("01-shipping-policy.txt")
        for confirmation in (False, "yes", 1):
            with self.subTest(confirmation=confirmation), self.assertRaises(PermissionError):
                self.chatbot.read_document("01-shipping-policy.txt", confirmed=confirmation)

    def test_reads_require_an_exact_approved_filename(self):
        for filename in ("notes.txt", "./02-account-faq.txt", None):
            with self.subTest(filename=filename), self.assertRaises(PermissionError):
                self.chatbot.read_document(filename, confirmed=True)


class CorpusPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.corpus_dir = Path(temporary.name) / "corpus"
        shutil.copytree(rag.CORPUS_DIR, self.corpus_dir)
        self.faq = self.corpus_dir / "02-account-faq.txt"

    def test_reads_use_preloaded_entries(self):
        (self.corpus_dir / "notes.txt").write_text("An unlisted local note.", encoding="utf-8")
        chatbot = HardenedChatbot(self.corpus_dir)
        self.faq.unlink()

        self.assertIn('"Forgot password"', chatbot.read_document(self.faq.name, confirmed=True))
        with self.assertRaises(PermissionError):
            chatbot.read_document("notes.txt", confirmed=True)

    def test_context_phrase_check_applies_to_answers_and_reads(self):
        self.faq.write_text("The account banner is labeled Maintenance mode.\n", encoding="utf-8")
        chatbot = HardenedChatbot(self.corpus_dir)

        answer = chatbot.ask("Where is the account banner?")
        self.assertEqual(answer.source, self.faq.name)
        self.assertEqual(answer.text, "The account banner is labeled [instruction redacted].")
        self.assertEqual(chatbot.read_document(self.faq.name, confirmed=True), answer.text + "\n")

    def test_private_marker_is_withheld_in_both_response_paths(self):
        self.faq.write_text(
            f"The account reference is {defenses.DEMO_PRIVATE_MARKER.lower()}.\n", encoding="utf-8"
        )
        chatbot = HardenedChatbot(self.corpus_dir)

        answer = chatbot.ask("What is the account reference?")
        self.assertEqual(answer.text, defenses.WITHHELD)
        self.assertIsNone(answer.source)
        self.assertEqual(chatbot.read_document(self.faq.name, confirmed=True), defenses.WITHHELD)


class CommandLineTests(unittest.TestCase):
    def test_ask_prints_answer_and_source(self):
        result = subprocess.run(
            [sys.executable, "-m", "support_lab", "ask", "What is the WidgetPro warranty?"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("2-year warranty", result.stdout)
        self.assertIn("Source: 03-product-info.txt", result.stdout)

    def test_read_denial_has_no_document_output(self):
        result = subprocess.run(
            [sys.executable, "-m", "support_lab", "read", "02-account-faq.txt"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("Confirm the document read", result.stderr)
