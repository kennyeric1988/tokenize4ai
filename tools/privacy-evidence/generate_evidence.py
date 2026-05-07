#!/usr/bin/env python3
"""Generate an audit evidence bundle from scanner findings and inventory data."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PLAYBOOK_BY_EXPOSURE = {
    "api_or_presentation": "API Response Masking",
    "observability": "Log And Trace Sanitization",
    "storage": "Data Pipeline Masking",
    "admin_or_export": "Admin, Support, BI, And Export Masking",
    "data_pipeline": "Data Pipeline Masking",
    "unknown": "Shared Rules",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    exposure = finding.get("exposure", "unknown")
    return {
        "finding_id": finding["id"],
        "source": {
            "file": finding.get("file", ""),
            "line": finding.get("line", 0),
            "rule_id": finding.get("rule_id", ""),
            "code_excerpt": finding.get("code_excerpt", ""),
            "matched_text": finding.get("matched_text", ""),
        },
        "classification": {
            "category": finding.get("category", "unknown"),
            "policy": finding.get("recommended_policy", "unknown"),
            "severity": finding.get("severity", "low"),
            "confidence": finding.get("confidence", "low"),
            "exposure": exposure,
            "llm_rationale": "Pending AI classification enrichment.",
        },
        "remediation": {
            "required": True,
            "playbook": PLAYBOOK_BY_EXPOSURE.get(exposure, "Shared Rules"),
            "diff_refs": [],
            "notes": "Generated from deterministic scanner output; attach remediation diff before closure.",
        },
        "verification": {
            "tests": [],
            "scanner_result": "pending",
        },
        "status": "open",
    }


def build_summary(systems: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, int]:
    open_findings = [item for item in findings if item["status"] == "open"]
    high_or_critical = [
        item
        for item in findings
        if item["classification"]["severity"] in {"critical", "high"} and item["status"] == "open"
    ]
    return {
        "system_count": len(systems),
        "finding_count": len(findings),
        "open_finding_count": len(open_findings),
        "critical_or_high_count": len(high_or_critical),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate sensitive data masking evidence bundle.")
    parser.add_argument("--findings", type=Path, required=True, help="Scanner findings JSON.")
    parser.add_argument("--inventory", type=Path, required=True, help="System inventory JSON.")
    parser.add_argument("--output", type=Path, required=True, help="Evidence bundle output path.")
    args = parser.parse_args()

    finding_report = load_json(args.findings)
    inventory = load_json(args.inventory)
    systems = inventory.get("systems", [])
    finding_evidence = [
        build_finding_evidence(item)
        for item in finding_report.get("findings", [])
        if item.get("type") != "scanner_error"
    ]

    bundle = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": build_summary(systems, finding_evidence),
        "systems": systems,
        "findings": finding_evidence,
        "approvals": [],
        "exceptions": [],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
