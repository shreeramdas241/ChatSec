"""ChatSec AI command line."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from catalog import MODULES, TOOL_NAME
from errors import ConfigError, IntegrationUnavailable, ScopeError
from scanner import run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chatsec", description="Security tests for AI chatbots.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run the configured security modules and write a report.")
    scan.add_argument("--config", required=True, help="Path to the target YAML file.")
    scan.add_argument("--output", default="reports", help="Directory for JSON and Markdown reports.")
    scan.add_argument("--tests", default="", help="Comma-separated module ids to run instead of the config list.")
    scan.add_argument(
        "--strict",
        action="store_true",
        help="Also exit 1 when a module is inconclusive or still needs instrumentation or verification.",
    )

    demo = sub.add_parser("serve-demo", help="Start the local demo chatbot.")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--port", type=int, default=8765)
    demo.add_argument("--mode", choices=("secure", "vulnerable"), default="secure")

    sub.add_parser("list-tests", help="Show the six modules and what each one has to prove.")

    args = parser.parse_args(argv)
    if args.command == "list-tests":
        print(TOOL_NAME)
        print("")
        for item in MODULES:
            print(f"{item['id']}")
            print(f"  Tests: {item['tests']}")
            print(f"  Proves: {item['proves']}")
        return 0
    if args.command == "serve-demo":
        from demo.server import serve

        serve(args.host, args.port, args.mode)
        return 0
    selected = [item.strip() for item in args.tests.split(",") if item.strip()] or None
    try:
        return run_scan(args.config, args.output, selected, strict=args.strict)
    except (ConfigError, ScopeError, IntegrationUnavailable) as exc:
        print(f"error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
