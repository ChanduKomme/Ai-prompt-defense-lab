"""Rule-based prompt-injection detector with risk scoring.

Author: Chandu Komme

Every rule maps to an OWASP Top 10 for LLM Applications (2025) category:

* LLM01 Prompt Injection
* LLM02 Sensitive Information Disclosure
* LLM06 Excessive Agency
* LLM07 System Prompt Leakage

Each text is scanned in all of its normalized views (see ``normalize``), so
hidden, spaced, leetspeak and encoded payloads are caught. Findings combine
with a noisy-OR, so independent signals reinforce each other without the
score ever passing 100:

    risk = 100 * (1 - prod(1 - severity_i / 100))

Decisions for the ``user`` channel: block at 60 or more, flag at 30 or more.
The ``context`` channel (retrieved documents) is stricter: any finding of
severity 40 or more marks the passage as untrusted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from .normalize import views

__author__ = "Chandu Komme"

BLOCK_AT = 60
FLAG_AT = 30
CONTEXT_UNTRUSTED_AT = 40


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    owasp: str
    severity: int
    pattern: re.Pattern
    channels: tuple[str, ...] = ("user", "context")
    description: str = ""


def _r(expr: str) -> re.Pattern:
    return re.compile(expr, re.I | re.S)


RULES: tuple[Rule, ...] = (
    Rule("PI-001", "instruction_override", "LLM01", 70,
         _r(r"\b(?:ignore|disregard|forget|override|skip)\s+(?:(?:all|any|every|the|your|my|these|those)\s+){0,2}"
            r"(?:previous|prior|above|earlier|preceding|original|initial|system)\s+"
            r"(?:instructions?|rules?|prompts?|directions?|guidelines?|messages?|context)\b"),
         description="Asks the model to drop its earlier instructions."),
    Rule("PI-002", "instruction_override", "LLM01", 55,
         _r(r"\b(?:new|updated|real|actual|revised)\s+(?:system\s+)?instructions?\s*[:\-]|\bfrom now on,?\s+you\s+(?:are|will|must|shall)\b"),
         description="Introduces replacement instructions."),
    Rule("PI-003", "jailbreak_roleplay", "LLM01", 65,
         _r(r"\b(?:dan|do anything now|developer mode|god mode|jailbreak(?:en|ed)?|aim mode)\b"
            r"|\b(?:act|behave|respond|pretend|roleplay|role-play|play)\s+(?:to\s+be\s+|as\s+|like\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|evil|rogue|jailbroken)\b"
            r"|\b(?:ignores?|without|no)\s+(?:any\s+)?(?:ethics|morals|guidelines|safety rules)\b"
            r"|\bwithout\s+(?:any\s+)?(?:restrictions|filters|limitations|rules|ethics)\b"),
         channels=("user",), description="Role-play or mode switch meant to remove safeguards."),
    Rule("PI-004", "policy_bypass", "LLM01", 60,
         _r(r"\b(?:bypass|disable|turn off|deactivate|remove|ignore)\s+(?:your\s+|the\s+|all\s+)?"
            r"(?:safety|safeguards?|guardrails?|filters?|content polic(?:y|ies)|moderation|restrictions)\b"),
         description="Asks to switch off safety controls."),
    Rule("LEAK-001", "prompt_extraction", "LLM07", 70,
         _r(r"\b(?:reveal|print|repeat|show|output|dump|display|tell me|share|leak|recite)\b.{0,40}"
            r"\b(?:system|hidden|initial|original|secret|internal)\s+(?:prompt|instructions?|message|rules|configuration)\b"),
         channels=("user",), description="Requests the hidden system prompt."),
    Rule("LEAK-002", "prompt_extraction", "LLM07", 55,
         _r(r"\b(?:repeat|print|output)\s+(?:everything|all|the\s+(?:text|words))\s+(?:above|before|preceding)\b"
            r"|\bwhat\s+(?:were|are)\s+(?:your|the)\s+(?:exact\s+)?(?:instructions|rules|guidelines)\b"),
         channels=("user",), description="Indirect way to make the model echo its prompt."),
    Rule("TOOL-001", "tool_injection", "LLM06", 75,
         _r(r"\b(?:send_email|issue_refund|read_document|lookup_order|delete_\w+|transfer_\w+|run_\w+|exec)\s*\("),
         description="Embeds a literal tool call."),
    Rule("TOOL-002", "tool_injection", "LLM06", 65,
         _r(r"\b(?:send|email|forward|mail|post|upload)\b.{0,80}\bto\s+[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
         channels=("context",), description="Retrieved text tells the agent to send data to an address."),
    Rule("EXFIL-001", "data_exfiltration", "LLM02", 75,
         _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*\)"),
         description="Markdown image whose URL carries data in its query string."),
    Rule("EXFIL-002", "data_exfiltration", "LLM02", 60,
         _r(r"\b(?:append|add|include|encode|put)\b.{0,60}\b(?:to|in|into)\s+(?:the\s+|this\s+)?(?:url|link|image|query string)\b"),
         description="Asks to smuggle data into a URL."),
    Rule("OBF-001", "obfuscation", "LLM01", 45,
         _r(r"\b(?:decode|base64|rot-?13|hex|reverse)\b.{0,40}\b(?:then|and)\s+(?:follow|execute|run|obey|do)\b"),
         description="Asks to decode and follow a hidden payload."),
    Rule("CTX-001", "embedded_role_marker", "LLM01", 55,
         _r(r"(?:^|\n)\s*(?:system|assistant|developer)\s*:|<\|?(?:system|im_start)\|?>|\[/?inst\]|###\s*(?:system|instruction)"),
         description="Fake chat-role markers inside text."),
    Rule("CTX-002", "concealment", "LLM01", 50,
         _r(r"\b(?:do not|don't|never)\s+(?:tell|mention|reveal|inform|show)\s+(?:this\s+to\s+)?(?:the\s+)?(?:user|customer|human)\b"),
         description="Asks the model to hide something from the user."),
    Rule("CTX-003", "hidden_instruction", "LLM01", 45,
         _r(r"<!--.{0,400}?\b(?:assistant|ai|model|bot|llm|instruction)\b.{0,400}?-->"),
         channels=("context",), description="Instruction hidden in an HTML comment."),
    Rule("SOC-001", "authority_claim", "LLM01", 40,
         _r(r"\b(?:i am|i'm|this is)\s+(?:the|an?|your)\s+(?:admin(?:istrator)?|developer|ceo|security team|openai|anthropic|system owner)\b.{0,60}"
            r"\b(?:override|authori[sz]e|grant|unlock|allow|permission)\b"),
         channels=("user",), description="Claims special authority to unlock behavior."),
)


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str
    owasp: str
    severity: int
    view: str
    match: str


@dataclass
class Assessment:
    channel: str
    risk: int
    decision: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        return {"channel": self.channel, "risk": self.risk, "decision": self.decision,
                "findings": [f.__dict__ for f in self.findings]}


def combine(severities: list[int]) -> int:
    remaining = 1.0
    for severity in severities:
        remaining *= 1 - severity / 100
    return round(100 * (1 - remaining))


def scan(text: str, channel: str = "user") -> Assessment:
    if channel not in ("user", "context"):
        raise ValueError("channel must be 'user' or 'context'")
    findings: dict[str, Finding] = {}
    for view in views(text):
        for rule in RULES:
            if channel not in rule.channels or rule.id in findings:
                continue
            match = rule.pattern.search(view.text)
            if match:
                snippet = " ".join(match.group(0).split())[:120]
                findings[rule.id] = Finding(rule.id, rule.category, rule.owasp, rule.severity, view.name, snippet)
    ordered = sorted(findings.values(), key=lambda f: (-f.severity, f.rule))
    risk = combine([f.severity for f in ordered])
    if channel == "user":
        decision = "block" if risk >= BLOCK_AT else "flag" if risk >= FLAG_AT else "allow"
    else:
        decision = "untrusted" if any(f.severity >= CONTEXT_UNTRUSTED_AT for f in ordered) else "trusted"
    return Assessment(channel, risk, decision, ordered)
