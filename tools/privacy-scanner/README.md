# Privacy Scanner

`privacy_scanner.py` is a deterministic first-pass scanner for sensitive data masking risks. It is designed to feed an AI classification and remediation loop, not to be the only source of truth.

## Usage

```bash
python3 tools/privacy-scanner/privacy_scanner.py --root . --output docs/ai-sdlc/evidence/findings.json
```

In CI, start with advisory mode:

```bash
python3 tools/privacy-scanner/privacy_scanner.py --root . --fail-on none
```

After tuning false positives, enforce high-confidence risks:

```bash
python3 tools/privacy-scanner/privacy_scanner.py --root . --fail-on critical
```

By default, the scanner excludes this toolkit's own `docs/ai-sdlc/` and `tools/privacy-*` paths to avoid policy-example self-noise when the toolkit is copied into an application repository. Use `--scan-toolkit` to scan those assets too, or pass additional `--exclude-path` regexes for generated folders.

## AI Classification Contract

Every finding includes `llm_classification_status: pending`. An AI classifier should enrich each finding with:

- whether the field is truly user-sensitive;
- whether the exposure is real or only a declaration;
- the final masking policy;
- remediation location and acceptance criteria;
- reviewer or exception requirement.

The original deterministic finding should remain immutable so evidence bundles can trace AI decisions back to source facts.
