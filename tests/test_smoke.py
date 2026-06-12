"""Smoke tests for GUARDPOST — runs the engine against the bundled demo."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardpost import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, Policy, RateLimiter, guard, redact, scan_pii,
)
from guardpost.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic", "agent_request.txt")


def _demo_text():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return fh.read()


def test_metadata():
    assert TOOL_NAME == "guardpost"
    assert TOOL_VERSION.count(".") == 2


def test_demo_is_blocked_and_redacted():
    text = _demo_text()
    result = guard(text, policy=Policy.strict(), principal="relay-1")
    # The injection / exfil attempt must force a block.
    assert result.blocked is True
    kinds = {f.kind for f in result.findings}
    # Real detections, not fake data.
    for expected in ("prompt_injection", "email", "credit_card", "ssn",
                     "api_key", "aws_access_key", "ipv4"):
        assert expected in kinds, f"missing detector: {expected}"
    # Raw secrets must NOT survive into sanitized output.
    assert "4111 1111 1111 1111" not in result.sanitized_text
    assert "123-45-6789" not in result.sanitized_text
    assert "jane.doe@acme-corp.com" not in result.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "[EMAIL]" in result.sanitized_text


def test_luhn_validation_rejects_random_digits():
    # 16 zeros are not a valid card -> no credit_card finding.
    bad = "order number 0000 0000 0000 0000 placed"
    assert not any(k == "credit_card" for k, *_ in scan_pii(bad))
    # A Luhn-valid number is detected.
    good = "card 4111111111111111 on file"
    assert any(k == "credit_card" for k, *_ in scan_pii(good))


def test_clean_text_allowed():
    result = guard("Please summarize the quarterly revenue trend.", policy=Policy())
    assert result.allowed is True
    assert result.findings == []


def test_redact_preserves_non_pii():
    out, findings = redact("contact bob@x.io now")
    assert out == "contact [EMAIL] now"
    assert len(findings) == 1


def test_rate_limiter_sliding_window():
    limiter = RateLimiter(limit=2, window_sec=10.0)
    t = 1000.0
    assert limiter.check("p", now=t) is True
    assert limiter.check("p", now=t) is True
    assert limiter.check("p", now=t) is False          # over limit
    assert limiter.check("p", now=t + 11) is True       # window slid past


def test_cli_blocks_demo_with_nonzero_exit():
    rc = main(["scan", DEMO, "--strict", "--format", "json"])
    assert rc == 2  # EXIT_BLOCKED


def test_cli_version():
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0


if __name__ == "__main__":
    test_metadata()
    test_demo_is_blocked_and_redacted()
    test_luhn_validation_rejects_random_digits()
    test_clean_text_allowed()
    test_redact_preserves_non_pii()
    test_rate_limiter_sliding_window()
    test_cli_blocks_demo_with_nonzero_exit()
    print("all smoke tests passed")
