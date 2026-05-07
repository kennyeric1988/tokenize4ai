# Pilot Rollout

Start with 1-3 representative department-owned systems before expanding to the full department.

## Pilot Selection

Choose systems that cover distinct exposure patterns:

- one user-facing or internal API service;
- one logging-heavy backend service or worker;
- one admin, export, BI, or data pipeline system.

## Pilot Exit Criteria

- Inventory records are complete enough for owner approval.
- Scanner findings have been reviewed against sampled source code.
- AI classification reaches acceptable precision on high and critical findings.
- At least one remediation per major playbook has been applied or dry-run.
- Tests prove raw sensitive values are absent from remediated surfaces.
- Evidence bundles can be generated without manual assembly.
- CI runs in advisory mode and uploads evidence artifacts.
- Exceptions are owner-bound, control-bound, and expiry-bound.

## Expansion Plan

1. Run inventory discovery across all department-owned repositories.
2. Group services by runtime, framework, and exposure type.
3. Apply the tuned scanner and playbooks to one group at a time.
4. Promote CI from advisory to blocking for critical findings.
5. Add recurring full scans and exception-expiry reviews.
6. Maintain scanner rule precision through sampled human review.

## Operating Metrics

- inventory coverage by service;
- finding count by category and exposure;
- high and critical findings open longer than target SLA;
- AI-generated remediation acceptance rate;
- false positive rate by rule;
- evidence bundle completeness;
- exception count and average age.
