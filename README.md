# AI Prompt Defense Lab

A small Python lab for testing a support chatbot's answers and document access. It uses three bundled ACME demo documents and runs offline with the Python standard library.

## Run locally

From the repository root, use Python 3.10 or later.

```sh
python -m support_lab ask "How long does standard shipping take?"
```

```text
ACME Shipping Policy: Standard shipping takes 3-5 business days.
Source: 01-shipping-policy.txt
```

Read the full account FAQ by approving that document explicitly.

```sh
python -m support_lab read 02-account-faq.txt --confirm
```

## What changed from Project 07

| Before | Change | Where |
| --- | --- | --- |
| The offline simulator returned the context wrapper for ordinary questions. | Keyword matching now selects a passage and includes its source filename. Queries without a matching passage return a clear fallback. | `support_lab/rag.py`, `support_lab/chatbot.py` |
| Approved filenames were missing from the mock file store. | The chatbot loads the three approved documents at startup. The explicit read command uses that same corpus and requires `--confirm`. | `data/corpus/`, `support_lab/chatbot.py`, `support_lab/__main__.py` |
| The output check covered the answer field. | Both response paths check for the same synthetic private-data marker. When the check withholds an answer, the CLI displays only the withholding message. | `support_lab/defenses.py`, `support_lab/chatbot.py` |
| The saved evaluation described simulated attack outcomes. | The standalone suite checks supported answers, provenance, authorization decisions, and output handling with inert local fixtures. | `tests/test_chatbot.py` |

`support_lab/__main__.py` adds the command-line entry point. `.gitignore` excludes local Python caches and environment files.

## Run the regression tests

```sh
python -m unittest discover -s tests -v
```

The tests exercise shipping, account, and product questions, all three approved reads, denied reads, and both response paths with a synthetic private-data marker. They also check the CLI's answer and denial behavior.

## How the lab handles input

The chatbot searches the preloaded support documents for a passage with at least two shared keywords. It returns an excerpt and its source when it finds a match. To request a full document through the chatbot, use the read command with the exact approved filename and confirmation. Phrase rules flag selected user wording and redact selected phrases in the corpus. Keyword matching can miss paraphrases, and phrase rules can flag legitimate wording. The output check recognizes the single synthetic marker used by the tests.

## Attribution

Adapted from Sanjeev Jaiswal's [Project 07 in `jassics/ai-security-projects`](https://github.com/jassics/ai-security-projects/tree/3ea65ff7a4bf1d8c74f54e4271ab36275c015bdc/07-ai-redteam-lab). The original MIT license and copyright notice are included in [LICENSE](LICENSE).
