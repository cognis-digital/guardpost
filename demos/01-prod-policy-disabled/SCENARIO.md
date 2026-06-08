# Scenario: Catastrophic prod policy

Someone disabled all the guardrails for 'debugging' and pushed to prod.

## Expected findings

- GP-POLICY-001 NO_RATE_LIMIT
- GP-POLICY-002 NO_PII_REDACTION (critical)
- GP-POLICY-003 INJECTION_BLOCK_OFF
- GP-POLICY-004 OUTPUT_FILTER_OFF

## Why this matters

Every red flag a CISO wants to know about, in one file.
