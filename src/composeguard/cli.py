from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from composeguard import __version__
from composeguard.analyzer import Finding, Severity, analyze_file

# ANSI escapes. Stdlib-only on purpose — no `colorama` / `rich` dependency.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_YELLOW = "\033[33m"
_GREY = "\033[90m"
_BRIGHT_RED = "\033[91m"

# Severity → ANSI prefix. Roughly mirrors Grype's palette: high = bold red,
# medium = yellow, low = grey.
_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.HIGH: _BOLD + _BRIGHT_RED,
    Severity.MEDIUM: _YELLOW,
    Severity.LOW: _GREY,
}


def _supports_color(mode: str) -> bool:
    """Resolve the --color flag (always|never|auto) into a bool."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    # auto: honor https://no-color.org and only color real TTYs.
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _format_finding(path: Path, finding: Finding, *, use_color: bool) -> str:
    severity_str = f"{finding.severity.value.upper():<8}"
    if use_color:
        severity_str = f"{_SEVERITY_COLOR[finding.severity]}{severity_str}{_RESET}"
    location = f"{path}::{finding.service}" if finding.service else str(path)
    return f"{severity_str} {location}  {finding.rule_id}  {finding.message}"


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
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Colorize the severity column. (default: auto — color when stdout is a TTY)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    threshold = Severity(args.fail_on)
    use_color = _supports_color(args.color)

    worst = Severity.LOW
    total = 0
    for path in args.files:
        findings = analyze_file(path)
        total += len(findings)
        for finding in findings:
            print(_format_finding(path, finding, use_color=use_color))
            if finding.severity.rank > worst.rank:
                worst = finding.severity

    print(f"\n{total} finding(s) across {len(args.files)} file(s).")
    return 1 if worst.rank >= threshold.rank and total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
