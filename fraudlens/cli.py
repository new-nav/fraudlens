"""Command line interface:  python -m fraudlens <command>"""
from __future__ import annotations

import argparse
import sys

from .detector import (Verdict, analyze_collect_request, analyze_message,
                       analyze_transactions, parse_csv_text, summarize)
from .samples import SAMPLE_COLLECT, SAMPLE_MESSAGES, sample_csv_text

ICON = {"HIGH": "[!!!]", "MEDIUM": "[ ! ]", "LOW": "[ ok]"}


def print_verdict(v: Verdict, indent: str = "") -> None:
    print(f"{indent}{ICON[v.level]} {v.label.upper()}  (risk {v.score:.0%})")
    for s in v.signals:
        print(f"{indent}   - {s.title}: {s.detail}")
    for a in v.advice:
        print(f"{indent}   > {a}")


def cmd_message(args) -> int:
    text = open(args.file, encoding="utf-8").read() if args.file else " ".join(args.text)
    if not text.strip():
        print("Give some text, e.g.: python -m fraudlens message \"Your account is blocked, click ...\"", file=sys.stderr)
        return 2
    print_verdict(analyze_message(text))
    return 0


def cmd_collect(args) -> int:
    print_verdict(analyze_collect_request(args.vpa, args.amount, args.note or "", args.name or "", args.expecting, args.typical))
    return 0


def cmd_transactions(args) -> int:
    text = sample_csv_text() if args.sample else open(args.csv, encoding="utf-8").read()
    try:
        alerts = analyze_transactions(parse_csv_text(text))
    except ValueError as exc:
        print(f"Could not read transactions: {exc}", file=sys.stderr)
        return 2
    s = summarize(alerts)
    print(f"{s['total']} transactions | {s['high']} high-risk | {s['medium']} suspicious | Rs {s['amount_at_risk']:,.0f} flagged\n")
    for a in alerts:
        if a.verdict.level == "LOW":
            continue
        t = a.tx
        print(f"{t.id} {t.timestamp:%d-%b %H:%M} {t.direction:6} Rs {t.amount:>9,.2f}  {t.counterparty}")
        print_verdict(a.verdict, indent="   ")
        print()
    return 0


def cmd_demo(_args) -> int:
    for name, text in SAMPLE_MESSAGES.items():
        print(f"=== Message: {name}\n    \"{text}\"")
        print_verdict(analyze_message(text), indent="    ")
        print()
    for name, c in SAMPLE_COLLECT.items():
        print(f"=== Collect request: {name} ({c['vpa']}, Rs {c['amount']})")
        print_verdict(analyze_collect_request(c["vpa"], c["amount"], c["note"], c["name"], c["expecting_money"]), indent="    ")
        print()
    return 0


def cmd_serve(args) -> int:
    from .server import serve
    serve(args.host, args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fraudlens", description="Scam & fraud detector for UPI (synthetic-data demo)")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("message", help="check an SMS / WhatsApp / email text")
    m.add_argument("text", nargs="*", help="the message text")
    m.add_argument("--file", help="read the message from a file instead")
    m.set_defaults(fn=cmd_message)

    c = sub.add_parser("collect", help="check a UPI collect request before approving")
    c.add_argument("--vpa", required=True, help="payee UPI ID, e.g. name@okaxis")
    c.add_argument("--amount", type=float, required=True)
    c.add_argument("--note", default="")
    c.add_argument("--name", default="")
    c.add_argument("--expecting", action="store_true", help="you believe you are about to RECEIVE money")
    c.add_argument("--typical", type=float, help="your typical payment amount")
    c.set_defaults(fn=cmd_collect)

    t = sub.add_parser("transactions", help="scan a transactions CSV for suspicious activity")
    g = t.add_mutually_exclusive_group(required=True)
    g.add_argument("csv", nargs="?", help="CSV file path")
    g.add_argument("--sample", action="store_true", help="use built-in synthetic data")
    t.set_defaults(fn=cmd_transactions)

    d = sub.add_parser("demo", help="run the detector on built-in examples")
    d.set_defaults(fn=cmd_demo)

    s = sub.add_parser("serve", help="start the local web app")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)
