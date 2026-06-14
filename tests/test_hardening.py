"""Hardening tests for GUARDPOST — edge cases, bad input, error paths."""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from guardpost.core import (
    Policy, RateLimiter, guard, redact, scan_pii,
    scan_policy, fingerprint,
)
from guardpost.cli import main, EXIT_ERROR, EXIT_OK


# ---------------------------------------------------------------------------
# core.py — guard() input validation
# ---------------------------------------------------------------------------

def test_guard_rejects_non_string():
    """guard() must raise TypeError for non-str input, not crash silently."""
    with pytest.raises(TypeError, match="str"):
        guard(None)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="str"):
        guard(42)  # type: ignore[arg-type]


def test_guard_empty_string_allowed():
    """Empty string is valid input and should produce no findings."""
    result = guard("", policy=Policy())
    assert result.allowed is True
    assert result.findings == []
    assert result.sanitized_text == ""


def test_guard_none_principal_falls_back():
    """Passing principal=None should not crash — defaults to 'anonymous'."""
    result = guard("hello", principal=None)  # type: ignore[arg-type]
    assert result.principal == "anonymous"


def test_guard_whitespace_only():
    """Whitespace-only text is valid and clean."""
    result = guard("   \n\t  ", policy=Policy())
    assert result.allowed is True
    assert result.findings == []


# ---------------------------------------------------------------------------
# core.py — RateLimiter input validation
# ---------------------------------------------------------------------------

def test_rate_limiter_rejects_negative_limit():
    with pytest.raises(ValueError, match="non-negative"):
        RateLimiter(limit=-1)


def test_rate_limiter_rejects_zero_window():
    with pytest.raises(ValueError, match="positive"):
        RateLimiter(limit=5, window_sec=0)


def test_rate_limiter_rejects_negative_window():
    with pytest.raises(ValueError, match="positive"):
        RateLimiter(limit=5, window_sec=-10.0)


def test_rate_limiter_limit_zero_always_blocks():
    """A limit of 0 should block every request immediately."""
    limiter = RateLimiter(limit=0, window_sec=60.0)
    assert limiter.check("user") is False


# ---------------------------------------------------------------------------
# core.py — fingerprint() input validation
# ---------------------------------------------------------------------------

def test_fingerprint_rejects_non_string():
    with pytest.raises(TypeError, match="str"):
        fingerprint(None)  # type: ignore[arg-type]


def test_fingerprint_empty_string():
    fp = fingerprint("")
    assert isinstance(fp, str)
    assert len(fp) == 16


# ---------------------------------------------------------------------------
# core.py — scan_pii / redact edge cases
# ---------------------------------------------------------------------------

def test_scan_pii_empty_string():
    assert scan_pii("") == []


def test_redact_empty_string():
    out, findings = redact("")
    assert out == ""
    assert findings == []


def test_scan_policy_empty_banned_terms():
    """Policy with empty banned_terms must not raise on clean text."""
    policy = Policy(banned_terms=())
    findings = scan_policy("hello world", policy)
    assert findings == []


def test_scan_policy_empty_text():
    """scan_policy on empty string returns no findings."""
    policy = Policy.strict()
    findings = scan_policy("", policy)
    assert findings == []


# ---------------------------------------------------------------------------
# cli.py — missing / unreadable file -> exit 1
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_exit_error():
    rc = main(["scan", "/no/such/file/at/all.txt"])
    assert rc == EXIT_ERROR


def test_cli_nonexistent_file_writes_to_stderr(capsys):
    main(["scan", "/definitely/does/not/exist.txt"])
    captured = capsys.readouterr()
    assert "guardpost:" in captured.err
    assert "cannot read" in captured.err


def test_cli_non_utf8_file_returns_exit_error():
    """A file with non-UTF-8 bytes should give exit 1, not a raw traceback."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\xff\xfe binary junk \x80\x81")
        fname = f.name
    try:
        rc = main(["scan", fname])
        assert rc == EXIT_ERROR
    finally:
        os.unlink(fname)


# ---------------------------------------------------------------------------
# cli.py — invalid --rate-limit argument -> exit 1
# ---------------------------------------------------------------------------

def test_cli_negative_rate_limit_returns_exit_error(capsys):
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("hello world")
        fname = f.name
    try:
        rc = main(["scan", fname, "--rate-limit", "-5"])
        assert rc == EXIT_ERROR
        captured = capsys.readouterr()
        assert "invalid argument" in captured.err
    finally:
        os.unlink(fname)


# ---------------------------------------------------------------------------
# cli.py — clean small file -> exit 0
# ---------------------------------------------------------------------------

def test_cli_clean_file_exits_ok():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("Please summarize the quarterly revenue report.")
        fname = f.name
    try:
        rc = main(["scan", fname])
        assert rc == EXIT_OK
    finally:
        os.unlink(fname)
