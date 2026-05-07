# Service Onboarding Checklist

Use this checklist when bringing a department-owned system into the sensitive data masking program.

## Inventory

- Service owner, repository, runtime, and deployment target are recorded.
- APIs, jobs, admin tools, exports, dashboards, and data stores are listed.
- Log, trace, metric, and alert sinks are listed.
- Known sensitive fields are mapped to taxonomy category and policy.
- External/shared dependencies are recorded as data-flow dependencies.

## Discovery

- Deterministic scanner has run on the repository.
- API specs, schemas, DTOs, serializers, log calls, SQL, and export paths were reviewed.
- AI classification has enriched findings with category, exposure, policy, and rationale.
- Findings are ranked by risk and grouped into remediation tasks.

## Remediation

- The matching playbook is selected for each task.
- Masking is applied at the boundary closest to output or persistence.
- Raw data access is removed, masked, tokenized, or protected by reveal controls.
- Generated tests cover API responses, logs, admin/export views, data pipelines, or fixtures as appropriate.

## Evidence

- Evidence bundle links findings, classification, remediation, verification, approvals, and exceptions.
- Open exceptions have owners, compensating controls, and expiry dates.
- CI scanner output is attached to the service compliance record.

## Rollout

- Advisory CI gate is enabled.
- High-confidence critical findings are blocked after tuning.
- Service owner signs off inventory accuracy.
- Privacy/security owner signs off policy exceptions.
