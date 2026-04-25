from __future__ import annotations

import argparse
import sys
from pathlib import Path

from composeguard import __version__
from composeguard.analyzer import Severity, analyze_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="composeguard",
        description="Static analyzer for docker-compose.yml that flags insecure configurations.",
    )
    parser.add_argument("--version", action="version", version=f"composeguard {__version__}")
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="Path(s) to docker-compose.yml file(s) to analyze.",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=Severity.HIGH.value,
        help="Exit non-zero if any finding is at this severity or higher (default: high).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    threshold = Severity(args.fail_on)

    worst = Severity.INFO
    total = 0
    for path in args.files:
        findings = analyze_file(path)
        total += len(findings)
        for finding in findings:
            print(f"{finding.severity.value.upper():8} {path}: {finding.rule_id} - {finding.message}")
            if finding.severity.rank > worst.rank:
                worst = finding.severity

    print(f"\n{total} finding(s) across {len(args.files)} file(s).")
    return 1 if worst.rank >= threshold.rank and total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
