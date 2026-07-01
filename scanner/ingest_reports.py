"""CLI to build the scanner's historical knowledge base from bug-bounty reports.

Usage:
    python -m scanner.ingest_reports --input bb_reports --output knowledge_base.json

The input reports and the generated knowledge base both stay local (git-ignored);
only this code is committed.
"""

from __future__ import annotations

import argparse
import sys

from .knowledge_base import KnowledgeBase


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse historical bug-bounty reports into a scanner knowledge base.",
    )
    parser.add_argument(
        "--input",
        default="bb_reports",
        help="Directory containing exported report files (default: bb_reports).",
    )
    parser.add_argument(
        "--output",
        default="knowledge_base.json",
        help="Path to write the generated knowledge base JSON (default: knowledge_base.json).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    kb = KnowledgeBase.from_reports(args.input)
    if not kb.findings:
        print(f"No parseable reports found in '{args.input}'.", file=sys.stderr)
        return 1

    kb.save(args.output)

    stats = kb.stats()
    print(f"Ingested {stats['total']} report(s) -> {args.output}")
    print("\nBy weakness class:")
    for name, count in sorted(stats["by_class"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {count:3}  {name}")
    print("\nHosts covered:")
    for host in stats["hosts"]:
        print(f"  {host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
