# AI Remediation Playbooks

These playbooks turn scanner findings into consistent implementation tasks. Agents should prefer central masking boundaries over scattered business-logic edits.

## Shared Rules

- Start from the taxonomy and policy catalog in `docs/ai-sdlc/`.
- Preserve raw values only where a policy explicitly permits it.
- Keep default UI, API, export, log, and evidence output masked.
- Add tests that prove raw sensitive values are absent from the remediated surface.
- Attach evidence linking the finding, decision, diff, test result, and reviewer or exception status.

## API Response Masking

Use this when a finding appears in controllers, serializers, DTOs, view models, GraphQL resolvers, REST handlers, or response mappers.

Steps:
1. Identify the response boundary closest to serialization.
2. Add masking in the response mapper or serializer, not deep in domain logic.
3. Update API contract examples to show masked values.
4. Add contract or integration tests that assert sensitive fields are masked.
5. Record any clients that require full values and route them through `access_controlled_reveal`.

Acceptance criteria:
- External and internal default responses do not expose raw sensitive values.
- Raw values remain available only inside authorized service logic.
- Tests fail when raw values appear in serialized output.

## Log And Trace Sanitization

Use this when a finding appears near logger calls, trace attributes, metrics labels, exception serialization, or request/response logging.

Steps:
1. Prefer a shared logger sanitizer or structured logging filter.
2. Drop credential and secret values instead of masking them.
3. Redact free-text payloads before logging.
4. Avoid high-cardinality identifiers in metrics labels.
5. Add tests around logger wrappers and representative direct call sites.

Acceptance criteria:
- Logs, traces, metrics, and exception payloads contain no raw credentials or direct identifiers.
- Unsafe direct logging call sites are removed or covered by a sanitizer.
- CI scanner runs on logging-heavy files.

## Admin, Support, BI, And Export Masking

Use this when a finding appears in admin screens, support tools, dashboards, reports, CSV exports, warehouse views, or scheduled files.

Steps:
1. Mask by default in query projections, view models, and export mappers.
2. Add explicit reveal workflows only for approved roles and purposes.
3. Audit every reveal with actor, field, reason, ticket, and timestamp.
4. Apply tokenization or hashing when downstream joins are required.
5. Add snapshot or golden-file tests for exports and admin views.

Acceptance criteria:
- Default screens and exports use the policy catalog treatment.
- Reveal paths require authorization and produce audit logs.
- Export tests assert no raw sensitive values in generated files.

## Data Pipeline Masking

Use this when a finding appears in ETL jobs, streams, message consumers, feature pipelines, warehouse jobs, or files sent to downstream systems.

Steps:
1. Classify source fields before transformation.
2. Mask before writing to less restricted sinks.
3. Keep raw data only in approved restricted stores with retention controls.
4. Add schema checks so new sensitive fields fail classification gates.
5. Create downstream consumer evidence for any unmasked dependency.

Acceptance criteria:
- Sensitive fields are masked or minimized before downstream writes.
- Pipeline tests include representative sensitive payloads.
- Data contracts document category and masking policy per field.

## Test Fixture And Snapshot Sanitization

Use this when raw sensitive examples appear in tests, mocks, fixtures, snapshots, docs, or generated samples.

Steps:
1. Replace realistic user data with synthetic values.
2. Sanitize snapshots and golden files.
3. Add scanner coverage for test directories.
4. Avoid copying production records into fixtures.

Acceptance criteria:
- Test assets contain no real-looking credentials, tokens, contact data, or direct identifiers.
- Snapshot updates fail review if raw sensitive values are introduced.

## Free-Text Redaction

Use this when comments, notes, messages, support tickets, or error details may contain user-sensitive values.

Steps:
1. Apply detector-based redaction before display, logging, export, or model training.
2. Store raw free text only where there is a documented purpose and retention policy.
3. Add test cases for email, phone, token, IP, and multilingual free text.
4. Measure false positives and false negatives with sampled review.

Acceptance criteria:
- Free text is redacted at every output boundary.
- Detector tests cover common sensitive substrings.
- Known false positive tradeoffs are documented in evidence.
