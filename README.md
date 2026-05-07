# AI-SDLC Sensitive Data Masking Toolkit

This repository contains reusable assets for an AI-first compliance program that discovers, classifies, remediates, verifies, and governs user-sensitive information masking across department-owned systems.

The toolkit is intentionally lightweight and language-agnostic at the policy layer. The prototype tools use Python standard-library modules so they can run in CI and local developer environments without extra dependency setup.

## Contents

- `docs/ai-sdlc/sensitive-data-taxonomy.yaml`: canonical sensitive data categories.
- `docs/ai-sdlc/masking-policy-catalog.yaml`: approved masking policies and evidence expectations.
- `docs/ai-sdlc/pii-masking-compliance-plan.md`: executable program guide.
- `tools/privacy-inventory/`: inventory schema and example system record.
- `tools/privacy-scanner/`: deterministic scanner prototype and rule catalog.
- `tools/privacy-remediation/`: remediation playbooks and reusable masking helpers.
- `tools/privacy-evidence/`: evidence schema and bundle generator.

## Quick Start

Build a repository-first candidate inventory:

```bash
python3 tools/privacy-inventory/repo_inventory_scanner.py \
  --root . \
  --output docs/ai-sdlc/evidence/repo-inventory-scan.json \
  --pretty
```

Run the scanner against a repository:

```bash
python3 tools/privacy-scanner/privacy_scanner.py --root . --output docs/ai-sdlc/evidence/findings.json
```

Generate an evidence bundle from findings:

```bash
python3 tools/privacy-evidence/generate_evidence.py \
  --findings docs/ai-sdlc/evidence/findings.json \
  --inventory tools/privacy-inventory/inventory.example.json \
  --output docs/ai-sdlc/evidence/evidence-bundle.json
```

Use the generated evidence bundle as the audit trail for remediation work, CI gates, and service owner review.
