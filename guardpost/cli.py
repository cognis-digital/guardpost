"""GUARDPOST command-line interface.

Primary subcommand: ``scan`` — run the firewall over text or a file and emit
findings. Exit code is non-zero when traffic is BLOCKED (policy violation,
rate-limit breach, or high-severity PII left in plaintext), so it drops cleanly
into CI / shell pipelines:

    guardpost scan request.txt --strict --format json
    cat prompt.txt | guardpost scan - --redact
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Policy, guard, fingerprint


# Exit codes
EXIT_OK = 0
EXIT_BLOCKED = 2
EXIT_ERROR = 1


def _read_input(source: str) -> str:
    if source == "-":
        try:
            return sys.stdin.read()
        except UnicodeDecodeError as exc:
            raise OSError(f"stdin contains non-UTF-8 bytes: {exc}") from exc
    try:
        with open(source, "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError as exc:
        raise OSError(f"{source!r} contains non-UTF-8 bytes: {exc}") from exc


def _build_policy(args) -> Policy:
    if args.strict:
        policy = Policy.strict()
    else:
        policy = Policy()
    policy.redact_pii = args.redact
    if args.no_injection:
        policy.block_injection = False
    if args.ban:
        policy.banned_terms = tuple(args.ban)
    if args.allow_pii:
        policy.allowed_pii = tuple(args.allow_pii)
    if args.rate_limit is not None:
        if args.rate_limit < 0:
            raise ValueError(f"--rate-limit must be >= 0, got {args.rate_limit}")
        policy.rate_limit = args.rate_limit
    return policy


def _render_table(result, source: str) -> str:
    lines = []
    status = "BLOCKED" if result.blocked else "ALLOWED"
    lines.append(f"GUARDPOST  source={source}  principal={result.principal}  -> {status}")
    lines.append(f"fingerprint={fingerprint(result.sanitized_text)}  findings={len(result.findings)}")
    if result.findings:
        lines.append("-" * 68)
        lines.append(f"{'SEVERITY':<9} {'CATEGORY':<11} {'KIND':<22} EXCERPT")
        lines.append("-" * 68)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(result.findings, key=lambda x: order.get(x.severity, 9)):
            lines.append(f"{f.severity:<9} {f.category:<11} {f.kind:<22} {f.excerpt}")
    lines.append("-" * 68)
    lines.append("SANITIZED OUTPUT:")
    lines.append(result.sanitized_text)
    return "\n".join(lines)


def _cmd_scan(args) -> int:
    try:
        text = _read_input(args.source)
    except OSError as exc:
        sys.stderr.write(f"guardpost: cannot read {args.source!r}: {exc}\n")
        return EXIT_ERROR

    try:
        policy = _build_policy(args)
    except ValueError as exc:
        sys.stderr.write(f"guardpost: invalid argument: {exc}\n")
        return EXIT_ERROR

    try:
        result = guard(text, policy=policy, principal=args.principal)
    except Exception as exc:  # pragma: no cover — unexpected engine error
        sys.stderr.write(f"guardpost: internal error: {exc}\n")
        return EXIT_ERROR

    fmt = getattr(args, "scan_format", None) or args.format
    try:
        if fmt == "json":
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(_render_table(result, args.source))
    except (OSError, BrokenPipeError):
        pass  # output pipe closed — not an error

    return EXIT_BLOCKED if result.blocked else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Runtime agent firewall: PII redaction, policy enforcement, rate limits.")
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=("table", "json"), default="table",
                        help="output format (default: table)")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", help="scan text/file for PII & policy violations")
    scan.add_argument("source", nargs="?", default="-",
                      help="path to input file, or '-' for stdin (default: stdin)")
    scan.add_argument("--principal", default="anonymous",
                      help="identity used for rate limiting / audit")
    scan.add_argument("--redact", dest="redact", action="store_true", default=True,
                      help="redact PII in the sanitized output (default)")
    scan.add_argument("--no-redact", dest="redact", action="store_false",
                      help="do not redact; flag high-severity PII as a block")
    scan.add_argument("--strict", action="store_true",
                      help="use the strict built-in policy")
    scan.add_argument("--no-injection", action="store_true",
                      help="disable prompt-injection detection")
    scan.add_argument("--ban", action="append", metavar="TERM",
                      help="banned term that triggers a block (repeatable)")
    scan.add_argument("--allow-pii", action="append", metavar="KIND",
                      help="PII kind to permit, e.g. ipv4 (repeatable)")
    scan.add_argument("--rate-limit", type=int, metavar="N",
                      help="max requests per window for the principal")
    scan.add_argument("--format", choices=("table", "json"), dest="scan_format",
                      default=None, help="output format (overrides global --format)")
    scan.set_defaults(func=_cmd_scan)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
