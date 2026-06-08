# Scenario: Staging environment with selective disablement

QA staging where PII redaction is on but injection blocking is intentionally disabled. Output filter accidentally off.

## Expected findings

- GP-POLICY-003 INJECTION_BLOCK_OFF
- GP-POLICY-004 OUTPUT_FILTER_OFF

## Why this matters

Realistic mid-state. Useful to show GUARDPOST surfaces partial misconfig, not just disasters.
