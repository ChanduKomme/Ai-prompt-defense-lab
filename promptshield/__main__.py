"""Command line: ``python -m promptshield <command>``.

Author: Chandu Komme

Commands
    ask "question"        answer with the guarded agent (add --naive for the baseline)
    scan "text"           show detector findings and the risk score
    redteam               run the attack and benign suites, write a scorecard, apply the gate
    serve                 start the JSON HTTP API on 127.0.0.1
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__, detector, redteam
from .agents import GuardedAgent, NaiveAgent
from .retrieval import POISONED_DIR, load_documents

__author__ = "Chandu Komme"


def cmd_ask(args) -> int:
    extra = [d for d in load_documents(POISONED_DIR, trusted=False) if d.name in (args.poison or [])]
    agent = (NaiveAgent if args.naive else GuardedAgent)(extra)
    response = agent.answer(args.question, confirmed=args.confirm)
    if args.json:
        print(json.dumps(response.to_dict(), indent=2))
    else:
        print(response.text)
        if response.sources:
            print(f"\nSources: {', '.join(dict.fromkeys(response.sources))}")
        print(f"Decision: {response.decision} · risk {response.risk}"
              + (f" · quarantined {', '.join(response.quarantined)}" if response.quarantined else "")
              + (f" · {len(response.denied_calls)} tool call(s) denied" if response.denied_calls else ""))
        if agent.sandbox.harmful_effects:
            print(f"Side effects executed: {agent.sandbox.harmful_effects}")
    if args.audit and isinstance(agent, GuardedAgent):
        with Path(args.audit).open("a", encoding="utf-8") as handle:
            for record in agent.audit:
                handle.write(json.dumps(record) + "\n")
    return 0


def cmd_scan(args) -> int:
    print(json.dumps(detector.scan(args.text, args.channel).to_dict(), indent=2))
    return 0


def cmd_redteam(args) -> int:
    results = redteam.run()
    card = redteam.scorecard(results)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(card, encoding="utf-8")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    m, gate = results["metrics"], results["gate"]
    print(f"Attacks: {m['attacks']}  Benign: {m['benign']}")
    for kind in ("naive", "guarded"):
        k = m[kind]
        print(f"  {kind:8} attack success {k['attack_success']:.0%}  false positives {k['false_positive']:.0%}  utility {k['utility']:.0%}")
    print(f"Gate: {'PASSED' if gate['passed'] else 'FAILED'} {gate['checks']}")
    return 0 if gate["passed"] else 1


def cmd_serve(args) -> int:
    from .server import serve
    server = serve(args.host, args.port)
    print(f"PromptShield API on http://{args.host}:{server.server_address[1]} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="promptshield", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"PromptShield {__version__} by Chandu Komme")
    sub = parser.add_subparsers(dest="command", required=True)
    ask = sub.add_parser("ask", help="answer a question")
    ask.add_argument("question")
    ask.add_argument("--naive", action="store_true", help="use the undefended baseline agent")
    ask.add_argument("--poison", action="append", metavar="FILE", help="add a poisoned document from data/poisoned")
    ask.add_argument("--confirm", action="store_true", help="confirm side-effect tools")
    ask.add_argument("--json", action="store_true")
    ask.add_argument("--audit", metavar="PATH", help="append audit records as JSON lines")
    ask.set_defaults(func=cmd_ask)
    scan = sub.add_parser("scan", help="scan text with the detector")
    scan.add_argument("text")
    scan.add_argument("--channel", choices=("user", "context"), default="user")
    scan.set_defaults(func=cmd_scan)
    red = sub.add_parser("redteam", help="run the red-team suites and apply the gate")
    red.add_argument("--output", metavar="MD", help="write the Markdown scorecard")
    red.add_argument("--json", metavar="PATH", help="write full results as JSON")
    red.set_defaults(func=cmd_redteam)
    srv = sub.add_parser("serve", help="start the JSON HTTP API")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8080)
    srv.set_defaults(func=cmd_serve)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
