"""Supplemental phrase checks and synthetic output filtering."""

import re

_CONTEXT_PATTERNS = (
    re.compile(r"\bignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above).{0,30}(?:instructions|rules)\b", re.I),
    re.compile(r"\b(?:system instructions?|maintenance mode)\b", re.I),
    re.compile(r"\bdo not (?:mention|tell|reveal)\b", re.I),
    re.compile(r"\b(?:send_email|read_file)\s*\(", re.I),
)
_INPUT_PATTERNS = (
    re.compile(r"\bignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above)\b", re.I),
    re.compile(r"\b(?:reveal|print|repeat|show|dump)\b.{0,40}\bsystem (?:prompt|instructions?)\b", re.I),
    re.compile(r"\b(?:DAN|developer mode|do anything now|unfiltered|no restrictions)\b", re.I),
    re.compile(r"\b(?:bypass|disable) (?:the )?(?:safety|guardrail|filter|content policy)\b", re.I),
)

# Synthetic marker for exercising the output check in local tests.
DEMO_PRIVATE_MARKER = "LAB_PRIVATE_MARKER"
WITHHELD = "[response withheld: private marker detected]"


def sanitize_context(text: str) -> str:
    for pattern in _CONTEXT_PATTERNS:
        text = pattern.sub("[instruction redacted]", text)
    return text


def matches_input_rule(question: str) -> bool:
    return any(pattern.search(question) for pattern in _INPUT_PATTERNS)


def filter_output(text: str) -> tuple[str, bool]:
    if DEMO_PRIVATE_MARKER.casefold() in text.casefold():
        return WITHHELD, True
    return text, False
