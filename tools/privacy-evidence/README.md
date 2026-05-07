# Privacy Evidence

Evidence bundles connect scanner findings, classification decisions, remediation work, verification results, approvals, and exceptions. They are intended to be produced automatically for every service and stored with the relevant compliance record.

## Generate Evidence

```bash
python3 tools/privacy-scanner/privacy_scanner.py \
  --root . \
  --output docs/ai-sdlc/evidence/findings.json

python3 tools/privacy-evidence/generate_evidence.py \
  --findings docs/ai-sdlc/evidence/findings.json \
  --inventory tools/privacy-inventory/inventory.example.json \
  --output docs/ai-sdlc/evidence/evidence-bundle.json
```

## Closure Requirements

A finding can be marked `remediated` only when:

- the final category and masking policy are recorded;
- the remediation diff reference is attached;
- tests or scanner results prove the raw value is absent;
- required approvals or exceptions are linked;
- any exception has an owner, compensating controls, and expiry date.
