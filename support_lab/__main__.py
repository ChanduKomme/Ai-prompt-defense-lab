"""Command-line entry point for the offline lab."""

import argparse

from .chatbot import HardenedChatbot


def main() -> int:
    parser = argparse.ArgumentParser(description="Ask questions about the demo support corpus.")
    commands = parser.add_subparsers(dest="command", required=True)

    ask_parser = commands.add_parser("ask", help="find a sourced support answer")
    ask_parser.add_argument("question", help="support question in quotes")

    read_parser = commands.add_parser("read", help="read an approved demo document")
    read_parser.add_argument("filename", help="exact filename in the bundled corpus")
    read_parser.add_argument("--confirm", action="store_true", help="approve this read")

    args = parser.parse_args()
    try:
        chatbot = HardenedChatbot()
    except (OSError, UnicodeError):
        parser.error("could not load the bundled support documents")

    if args.command == "ask":
        answer = chatbot.ask(args.question)
        print(answer.text)
        if answer.source:
            print(f"Source: {answer.source}")
        return 0

    try:
        text = chatbot.read_document(args.filename, confirmed=args.confirm)
    except PermissionError as error:
        parser.error(str(error))
    print(text.rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
