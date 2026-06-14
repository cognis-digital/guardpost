"""GUARDPOST core engine — runtime agent firewall.

A standard-library-only firewall for LLM / agent traffic. It performs three
classes of work, all implemented with real logic (no stubs):

  1. PII redaction        -- detect & mask emails, phones, SSNs, credit cards,
                             IPv4, API keys/secrets, AWS keys.
  2. Policy enforcement   -- block prompt-injection / jailbreak / secret-exfil
                             patterns and a configurable banned-term list.
  3. Rate limiting        -- per-principal sliding-window token bucket.

The engine is deterministic and importable: feed it text + a Policy and it
returns a GuardResult describing findings, the sanitized text, and the
allow/block decision.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional


# --------------------------------------------------------------------------- #
# PII detectors
# --------------------------------------------------------------------------- #

def _luhn_ok(digits: str) -> bool:
    """Validate a candidate card number with the Luhn checksum."""
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    # Reject degenerate sequences (all identical digits, e.g. all zeros).
    if len(set(nums)) <= 1:
        return False
    total = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Each entry: (kind, compiled regex, optional validator(match_text)->bool)
_PII_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: _luhn_ok(m)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("api_key", re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|prod)?[-_]?[A-Za-z0-9]{16,}\b"), None),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b"), None),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), None),
    ("phone", re.compile(r"(?<![\w.])(?:\+?1[ .\-]?)?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-])\d{3}[ .\-]?\d{4}(?!\d)"), None),
]


# --------------------------------------------------------------------------- #
# Policy / prompt-injection detectors
# --------------------------------------------------------------------------- #

_INJECTION_PATTERNS = [
    ("prompt_injection", re.compile(
        r"ignore (?:all |the )?(?:previous|prior|above) (?:instructions|prompts|directions)", re.I)),
    ("prompt_injection", re.compile(
        r"disregard (?:all |the )?(?:previous|prior|above|system)", re.I)),
    ("jailbreak", re.compile(r"\b(?:DAN|do anything now|developer mode|jailbreak)\b", re.I)),
    ("system_override", re.compile(r"you are no longer (?:bound|restricted|an? )", re.I)),
    ("system_override", re.compile(r"\bnew (?:system )?(?:prompt|instructions)\s*:", re.I)),
    ("secret_exfil", re.compile(
        r"(?:reveal|print|show|leak|dump|repeat) (?:your |the )?(?:system prompt|instructions|api[ _]?key|secret|password|credential)", re.I)),
    ("role_hijack", re.compile(r"pretend (?:you are|to be) (?:an? )?(?:admin|root|developer|unrestricted)", re.I)),
]


@dataclass
class Policy:
    """Firewall policy configuration."""
    redact_pii: bool = True
    block_injection: bool = True
    banned_terms: tuple = ()                 # case-insensitive substrings -> block
    allowed_pii: tuple = ()                  # PII kinds to permit (not redact/flag)
    rate_limit: Optional[int] = None         # max requests per window per principal
    rate_window_sec: float = 60.0
    mask_char: str = "*"

    @classmethod
    def strict(cls) -> "Policy":
        return cls(redact_pii=True, block_injection=True,
                   banned_terms=("password dump", "exfiltrate"),
                   rate_limit=30, rate_window_sec=60.0)


@dataclass
class Finding:
    kind: str            # detector name, e.g. "email", "prompt_injection"
    category: str        # "pii" | "policy" | "rate_limit"
    severity: str        # "low" | "medium" | "high" | "critical"
    span: tuple          # (start, end) in the ORIGINAL text; (-1,-1) if N/A
    excerpt: str         # redacted/short sample of the match


@dataclass
class GuardResult:
    allowed: bool
    sanitized_text: str
    findings: list = field(default_factory=list)
    principal: str = "anonymous"

    @property
    def blocked(self) -> bool:
        return not self.allowed

    def to_dict(self) -> dict:
        d = asdict(self)
        d["blocked"] = self.blocked
        return d


_SEVERITY = {
    "ssn": "critical", "credit_card": "critical", "aws_access_key": "critical",
    "api_key": "high", "bearer_token": "high", "secret_exfil": "critical",
    "email": "medium", "phone": "medium", "ipv4": "low",
    "prompt_injection": "high", "jailbreak": "high", "system_override": "high",
    "role_hijack": "high", "banned_term": "high",
}


def _mask(text: str, mask_char: str) -> str:
    """Mask a sensitive token, keeping a tiny hint of length/shape."""
    if len(text) <= 4:
        return mask_char * len(text)
    return text[:2] + mask_char * (len(text) - 4) + text[-2:]


def scan_pii(text: str, allowed: Iterable[str] = ()) -> list:
    """Return (kind, start, end, matched_text) for every PII hit."""
    allowed = set(allowed)
    hits = []
    for kind, pattern, validator in _PII_PATTERNS:
        if kind in allowed:
            continue
        for m in pattern.finditer(text):
            matched = m.group(0)
            if validator and not validator(matched):
                continue
            hits.append((kind, m.start(), m.end(), matched))
    # Resolve overlaps: keep the longest / most specific match per span.
    hits.sort(key=lambda h: (h[1], -(h[2] - h[1])))
    resolved = []
    last_end = -1
    for kind, start, end, matched in hits:
        if start >= last_end:
            resolved.append((kind, start, end, matched))
            last_end = end
    return resolved


def redact(text: str, allowed: Iterable[str] = (), mask_char: str = "*") -> tuple:
    """Redact PII in text. Returns (sanitized_text, findings)."""
    hits = scan_pii(text, allowed)
    findings = []
    # Rebuild text replacing matches from the end to preserve offsets.
    out = text
    for kind, start, end, matched in sorted(hits, key=lambda h: h[1], reverse=True):
        label = f"[{kind.upper()}]"
        out = out[:start] + label + out[end:]
    for kind, start, end, matched in hits:
        findings.append(Finding(
            kind=kind, category="pii", severity=_SEVERITY.get(kind, "medium"),
            span=(start, end), excerpt=_mask(matched, mask_char)))
    return out, findings


def scan_policy(text: str, policy: Policy) -> list:
    """Detect prompt-injection / banned-term policy violations."""
    findings = []
    if policy.block_injection:
        for kind, pattern in _INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    kind=kind, category="policy",
                    severity=_SEVERITY.get(kind, "high"),
                    span=(m.start(), m.end()), excerpt=m.group(0)[:60]))
    for term in policy.banned_terms:
        low = text.lower()
        idx = low.find(term.lower())
        while idx != -1:
            findings.append(Finding(
                kind="banned_term", category="policy", severity="high",
                span=(idx, idx + len(term)), excerpt=term))
            idx = low.find(term.lower(), idx + 1)
    return findings


# --------------------------------------------------------------------------- #
# Rate limiting — sliding window per principal
# --------------------------------------------------------------------------- #

class RateLimiter:
    """In-memory sliding-window rate limiter keyed by principal."""

    def __init__(self, limit: int, window_sec: float = 60.0):
        if not isinstance(limit, int) or limit < 0:
            raise ValueError(f"RateLimiter limit must be a non-negative integer, got {limit!r}")
        if not isinstance(window_sec, (int, float)) or window_sec <= 0:
            raise ValueError(f"RateLimiter window_sec must be a positive number, got {window_sec!r}")
        self.limit = limit
        self.window = float(window_sec)
        self._events: dict = {}

    def check(self, principal: str, now: Optional[float] = None) -> bool:
        """Record a request. Return True if allowed, False if over the limit."""
        now = time.time() if now is None else now
        bucket = self._events.setdefault(principal, [])
        cutoff = now - self.window
        # Drop events outside the window.
        bucket[:] = [t for t in bucket if t > cutoff]
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


# --------------------------------------------------------------------------- #
# Top-level guard
# --------------------------------------------------------------------------- #

def fingerprint(text: str) -> str:
    """Stable short hash of input, useful for audit logs without storing text."""
    if not isinstance(text, str):
        raise TypeError(f"fingerprint() requires a str, got {type(text).__name__!r}")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def guard(text: str, policy: Optional[Policy] = None, principal: str = "anonymous",
          limiter: Optional[RateLimiter] = None, now: Optional[float] = None) -> GuardResult:
    """Run the full firewall pipeline over a piece of agent traffic.

    Decision rule: BLOCK if any policy violation, any critical/high PII when not
    redacting, or a rate-limit breach. Otherwise ALLOW (with PII redacted).
    """
    if not isinstance(text, str):
        raise TypeError(f"guard() text must be a str, got {type(text).__name__!r}")
    if principal is None:
        principal = "anonymous"
    policy = policy or Policy()
    findings: list = []
    sanitized = text

    # 1. PII
    if policy.redact_pii:
        sanitized, pii_findings = redact(text, policy.allowed_pii, policy.mask_char)
        findings.extend(pii_findings)
    else:
        # Not redacting: still report PII as findings.
        for kind, start, end, matched in scan_pii(text, policy.allowed_pii):
            findings.append(Finding(kind, "pii", _SEVERITY.get(kind, "medium"),
                                    (start, end), _mask(matched, policy.mask_char)))

    # 2. Policy violations
    policy_findings = scan_policy(text, policy)
    findings.extend(policy_findings)

    # 3. Rate limit
    rate_blocked = False
    if policy.rate_limit is not None:
        limiter = limiter or RateLimiter(policy.rate_limit, policy.rate_window_sec)
        if not limiter.check(principal, now=now):
            rate_blocked = True
            findings.append(Finding(
                kind="rate_limit_exceeded", category="rate_limit", severity="high",
                span=(-1, -1),
                excerpt=f"{principal} exceeded {policy.rate_limit}/{policy.rate_window_sec:g}s"))

    # Decision
    allowed = True
    if policy_findings:
        allowed = False
    if rate_blocked:
        allowed = False
    if not policy.redact_pii and any(
            f.category == "pii" and f.severity in ("high", "critical") for f in findings):
        allowed = False

    return GuardResult(allowed=allowed, sanitized_text=sanitized,
                       findings=findings, principal=principal)
