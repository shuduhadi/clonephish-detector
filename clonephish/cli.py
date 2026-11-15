"""Command-line interface for ClonePhish Detector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .domains import analyse_domain
from .pages import compare_pages

COLOURS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m", "NONE": "\033[92m"}
RESET = "\033[0m"


def _paint(verdict: str, use_colour: bool) -> str:
    return f"{COLOURS[verdict]}{verdict}{RESET}" if use_colour else verdict


def _print_finding(title: str, score: int, verdict: str, reasons: list[str], colour: bool) -> None:
    print(f"{title}\n  risk: {_paint(verdict, colour)} ({score}/100)")
    for reason in reasons:
        print(f"  - {reason}")
    print()


def cmd_domains(args) -> int:
    candidates = list(args.candidates)
    if args.file:
        candidates += [
            line.strip() for line in Path(args.file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    if not candidates:
        print("No candidate domains given.", file=sys.stderr)
        return 2

    findings = sorted(
        (analyse_domain(c, args.brand) for c in candidates),
        key=lambda f: f.score, reverse=True,
    )
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2, ensure_ascii=False))
    else:
        for f in findings:
            _print_finding(f.candidate, f.score, f.verdict, f.reasons, not args.no_colour)
    return 1 if any(f.score >= args.fail_at for f in findings) else 0


def cmd_page(args) -> int:
    reference = Path(args.reference).read_text(encoding="utf-8", errors="replace")
    suspect = Path(args.suspect).read_text(encoding="utf-8", errors="replace")
    finding = compare_pages(reference, suspect, args.brand, args.suspect_url or "")

    if args.suspect_url:
        dom = analyse_domain(args.suspect_url, args.brand)
        if dom.score:
            finding.add(min(30, dom.score // 2), f"Hosted on a lookalike domain ({dom.verdict}): {dom.candidate}")
            finding.details["domain"] = dom.as_dict()

    if args.json:
        print(json.dumps(finding.as_dict(), indent=2, ensure_ascii=False))
    else:
        _print_finding(f"{args.suspect} vs {args.reference}", finding.score, finding.verdict,
                       finding.reasons, not args.no_colour)
        print(f"  similarity breakdown: {finding.details['similarity_parts']}")
    return 1 if finding.score >= args.fail_at else 0


def cmd_ct(args) -> int:
    from .ct import scan_ct  # imported lazily: needs network + requests

    try:
        findings = scan_ct(args.brand, args.keyword, args.min_score)
    except Exception as exc:  # network errors, crt.sh timeouts
        print(f"CT lookup failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2, ensure_ascii=False))
    else:
        if not findings:
            print("No suspicious certificates found.")
        for f in findings:
            _print_finding(f.candidate, f.score, f.verdict, f.reasons, not args.no_colour)
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="clonephish",
        description="Detect lookalike domains and cloned login pages. For defensive use on brands you own or are authorised to protect.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--brand", required=True, help="Your real domain, e.g. mybank.co.za")
    common.add_argument("--json", action="store_true", help="Output JSON")
    common.add_argument("--no-colour", action="store_true", help="Plain text output")
    common.add_argument("--fail-at", type=int, default=70, help="Exit 1 if any score reaches this (default 70)")

    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("domains", parents=[common], help="Score candidate domains for lookalike tricks")
    d.add_argument("candidates", nargs="*", help="Domains or URLs to check")
    d.add_argument("-f", "--file", help="File with one domain per line")
    d.set_defaults(func=cmd_domains)

    pg = sub.add_parser("page", parents=[common], help="Compare a saved suspect page with your real page")
    pg.add_argument("--reference", required=True, help="Saved HTML of your real login page")
    pg.add_argument("--suspect", required=True, help="Saved HTML of the suspect page")
    pg.add_argument("--suspect-url", help="URL the suspect page was found at")
    pg.set_defaults(func=cmd_page)

    ct = sub.add_parser("ct", parents=[common], help="Search Certificate Transparency logs (crt.sh) for lookalikes")
    ct.add_argument("--keyword", help="Keyword to search (default: your domain's name)")
    ct.add_argument("--min-score", type=int, default=40, help="Only show names scoring at least this")
    ct.set_defaults(func=cmd_ct)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
