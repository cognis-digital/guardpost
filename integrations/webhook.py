#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.error
import urllib.request

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward guardpost JSON findings to a webhook URL.")
    ap.add_argument("--url", required=True, help="HTTP(S) endpoint to POST to")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra header in 'Key: Value' form (repeatable)")
    args = ap.parse_args()

    # Validate headers before touching the network.
    headers: list[tuple[str, str]] = []
    for h in args.header:
        if ":" not in h:
            print(f"webhook: invalid --header {h!r} (expected 'Key: Value')",
                  file=sys.stderr)
            return 1
        k, _, v = h.partition(":")
        k, v = k.strip(), v.strip()
        if not k:
            print(f"webhook: --header {h!r} has an empty key", file=sys.stderr)
            return 1
        headers.append((k, v))

    try:
        payload = sys.stdin.buffer.read()
    except Exception as e:  # pragma: no cover
        print(f"webhook: failed to read stdin: {e}", file=sys.stderr)
        return 1

    if not payload:
        print("webhook: empty payload from stdin — nothing to POST", file=sys.stderr)
        return 1

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers:
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"webhook error: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"webhook error: {e.reason}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
