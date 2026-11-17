# Changelog

## 1.0.0 — 2026-11-17

PromptShield rebuilt from the ground up by Chandu Komme.

### Added
- Text normalization against evasion: zero-width characters, Cyrillic and Greek look-alikes, leetspeak, letter spacing, and base64, hex and rot13 payloads.
- Prompt-injection detector with 15 rules mapped to the OWASP Top 10 for LLM Applications (LLM01, LLM02, LLM06, LLM07), noisy-OR risk scoring, and separate user and context channels.
- Northwind Gear knowledge base (6 articles) and 6 poisoned articles, one per indirect-injection technique.
- BM25 retrieval with stemming, query expansion and source citations.
- Context guard (quarantine and spotlighting) and output guard (canary leak check, link and image stripping, email, card and secret redaction).
- Tool sandbox and policy with taint tracking, allowlist, argument validation, a refund cap and human confirmation.
- A naive baseline agent and a guarded agent with an audit trail.
- Red-team harness with 33 attacks, 30 benign questions and a 6-attack frontier suite, a Markdown and JSON scorecard, and a CI gate.
- Command line (`ask`, `scan`, `redteam`, `serve`) and a JSON HTTP API.
- Unit and system tests, plus CI on Python 3.10–3.13.

### Removed
- The earlier `support_lab` prototype and its corpus.
