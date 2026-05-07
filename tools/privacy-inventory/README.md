# Privacy Inventory

The inventory records department-owned systems and the data flows that need masking governance. It is the source of truth for service onboarding, scanner targeting, owner approvals, and evidence bundles.

## Required Workflow

1. Create or update a system record using `inventory.schema.json`.
2. List repositories, runtime type, data stores, interfaces, observability sinks, data flows, known sensitive fields, and exceptions.
3. Run privacy scanners against every listed repository and attach findings to the system ID.
4. Keep exceptions owner-bound and expiry-bound.

## AI Agent Instructions

When generating inventory records, prefer exact evidence from source files, service catalogs, deployment manifests, API specs, database schemas, and observability configuration. If a value is inferred, mark the related data flow or field as `unknown` and include a follow-up task rather than inventing ownership or compliance status.

## Repository-First Discovery

Use `repo_inventory_scanner.py` when starting from source repositories:

```bash
python3 tools/privacy-inventory/repo_inventory_scanner.py \
  --root . \
  --output docs/ai-sdlc/evidence/repo-inventory-scan.json \
  --pretty
```

See `repo-scan-usage.md` for the Chinese usage guide, output schema, and human-confirmation workflow.
