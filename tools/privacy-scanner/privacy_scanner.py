#!/usr/bin/env python3
"""Deterministic sensitive data scanner for AI-SDLC privacy remediation.

The scanner is intentionally conservative: it finds likely sensitive fields and
unsafe exposure contexts, then emits structured JSON for LLM classification,
human sampling, remediation agents, and audit evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_RULES = Path(__file__).with_name("rules.json")
DEFAULT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".json",
    ".kt",
    ".md",
    ".php",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sql",
    ".swift",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
DEFAULT_EXCLUDE_PATH_PATTERNS = [
    r"(^|/)docs/ai-sdlc/",
    r"(^|/)tools/privacy-",
]
SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CONFIDENCE_SCORE = {"high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    policy: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    description: str


@dataclass(frozen=True)
class PathHint:
    pattern: re.Pattern[str]
    exposure: str


def load_rules(path: Path) -> tuple[list[Rule], list[PathHint], int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rules = [
        Rule(
            id=item["id"],
            category=item["category"],
            policy=item["policy"],
            severity=item["severity"],
            confidence=item["confidence"],
            pattern=re.compile(item["pattern"]),
            description=item["description"],
        )
        for item in payload["rules"]
    ]
    hints = [
        PathHint(pattern=re.compile(item["pattern"]), exposure=item["exposure"])
        for item in payload.get("path_hints", [])
    ]
    return rules, hints, int(payload.get("version", 1))


def is_excluded(relative_path: str, exclude_patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(relative_path) for pattern in exclude_patterns)


def iter_files(root: Path, extensions: set[str], exclude_patterns: list[re.Pattern[str]]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if is_excluded(relative, exclude_patterns):
            continue
        if path.suffix.lower() in extensions:
            yield path


def detect_exposure(relative_path: str, line: str, hints: list[PathHint]) -> str:
    haystack = f"{relative_path} {line}"
    for hint in hints:
        if hint.pattern.search(haystack):
            return hint.exposure
    return "unknown"


def risk_score(severity: str, confidence: str, exposure: str) -> int:
    score = SEVERITY_SCORE.get(severity, 1) * 10 + CONFIDENCE_SCORE.get(confidence, 1)
    if exposure in {"api_or_presentation", "observability", "admin_or_export"}:
        score += 5
    if exposure == "unknown":
        score -= 1
    return score


def fingerprint(parts: list[str]) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def scan_file(root: Path, path: Path, rules: list[Rule], hints: list[PathHint]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    relative = path.relative_to(root).as_posix()
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return [
            {
                "id": fingerprint([relative, "read_error", str(exc)]),
                "type": "scanner_error",
                "file": relative,
                "message": str(exc),
            }
        ]

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule in rules:
            match = rule.pattern.search(stripped)
            if not match:
                continue
            exposure = detect_exposure(relative, stripped, hints)
            findings.append(
                {
                    "id": fingerprint([relative, str(line_number), rule.id, match.group(0)]),
                    "rule_id": rule.id,
                    "category": rule.category,
                    "recommended_policy": rule.policy,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "exposure": exposure,
                    "risk_score": risk_score(rule.severity, rule.confidence, exposure),
                    "file": relative,
                    "line": line_number,
                    "matched_text": match.group(0),
                    "code_excerpt": stripped[:500],
                    "description": rule.description,
                    "llm_classification_status": "pending",
                }
            )
    return findings


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_category: dict[str, int] = {}
    by_exposure: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in findings:
        if finding.get("type") == "scanner_error":
            continue
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
        by_exposure[finding["exposure"]] = by_exposure.get(finding["exposure"], 0) + 1
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
    return {
        "total_findings": sum(by_category.values()),
        "by_category": dict(sorted(by_category.items())),
        "by_exposure": dict(sorted(by_exposure.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan source code for sensitive data masking risks.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root to scan.")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Scanner rule catalog.")
    parser.add_argument("--output", type=Path, help="Write JSON report to this path.")
    parser.add_argument(
        "--extensions",
        default=",".join(sorted(DEFAULT_EXTENSIONS)),
        help="Comma-separated file extensions to scan.",
    )
    parser.add_argument(
        "--exclude-path",
        action="append",
        default=list(DEFAULT_EXCLUDE_PATH_PATTERNS),
        help="Regex path pattern to exclude. Can be passed multiple times.",
    )
    parser.add_argument(
        "--scan-toolkit",
        action="store_true",
        help="Scan compliance toolkit docs and tools instead of excluding them by default.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "critical", "high", "medium", "low"],
        default="none",
        help="Exit non-zero if findings at or above this severity exist.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    extensions = {item.strip() for item in args.extensions.split(",") if item.strip()}
    exclude_values = [] if args.scan_toolkit else args.exclude_path
    exclude_patterns = [re.compile(value) for value in exclude_values]
    rules, hints, rules_version = load_rules(args.rules)

    findings: list[dict[str, Any]] = []
    for path in iter_files(root, extensions, exclude_patterns):
        findings.extend(scan_file(root, path, rules, hints))

    findings.sort(key=lambda item: (-int(item.get("risk_score", 0)), item.get("file", ""), item.get("line", 0)))
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": {
            "name": "privacy_scanner",
            "excluded_path_patterns": exclude_values,
            "rules_version": rules_version,
            "root": str(root),
        },
        "summary": build_summary(findings),
        "findings": findings,
    }

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on != "none":
        threshold = SEVERITY_SCORE[args.fail_on]
        has_blocker = any(SEVERITY_SCORE.get(item.get("severity", "low"), 1) >= threshold for item in findings)
        if has_blocker:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
