# Evidence — PromptShield

Results from real runs, collected by **Chandu Komme** on 2026-11-17.

## Summary

| Check | Result |
|---|---|
| Unit and system tests | 36 tests passing on Python 3.10, 3.11, 3.12 and 3.13 |
| Red team, naive agent | 100% of 33 attacks succeed (the baseline is genuinely vulnerable) |
| Red team, guarded agent | 0% of 33 attacks succeed |
| Benign questions | 0% false positives, 100% answered from the right article |
| HTTP API | Benign question answered from `01-shipping.md`; attack blocked at risk 91 (rules LEAK-001 and PI-001) |
| Frontier suite | 6 harder attacks scored risk 0 by the detector, yet the guarded agent held against all 6 |

## Contents

| Path | What it holds |
|---|---|
| [`ci-run/github-actions-44159325328.txt`](ci-run/github-actions-44159325328.txt) | Red-team gate, CLI demo, and HTTP API smoke-test output from GitHub Actions ([run](https://github.com/ChanduKomme/Ai-prompt-defense-lab/actions/runs/44159325328)) |
| [`screenshots/01-ci-green-with-scorecard.jpg`](screenshots/01-ci-green-with-scorecard.jpg) | The green CI run with the scorecard published in the job summary |
| [`local-run/scorecard.md`](local-run/scorecard.md) | Full scorecard: metrics, OWASP breakdown, every attack, and the frontier suite |
| [`local-run/redteam-results.json`](local-run/redteam-results.json) | Machine-readable results for every attack and benign question |
| [`local-run/demo-transcript.txt`](local-run/demo-transcript.txt) | The same poisoned article against both agents, plus a detector scan of a leetspeak attack |

The red-team results are deterministic: the local run and the CI run produce the same metrics.

---
*PromptShield — by [Chandu Komme](https://github.com/ChanduKomme)*
