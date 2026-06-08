# Scenario: Multi-environment policy comparison

Same scan over dev/ and prod/ to highlight that dev is wide-open but prod is hardened.

## Expected findings

- 4 findings in dev.yaml; 0 in prod.yaml

## Why this matters

Run during release reviews: `guardpost scan demos/03-multi-env/` shows posture per-env.
