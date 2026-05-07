#!/usr/bin/env python3
"""Repository inventory scanner for sensitive data compliance.

This scanner builds a candidate asset and data-flow inventory from source code.
It intentionally favors broad coverage and evidence over perfect static
analysis. The output should be reviewed by AI and humans before it becomes the
authoritative department inventory.
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


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".swift",
    ".ts",
    ".tsx",
}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".xml", ".properties", ".proto", ".sql", ".md"}
SCAN_EXTENSIONS = SOURCE_EXTENSIONS | CONFIG_EXTENSIONS
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
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


@dataclass(frozen=True)
class Evidence:
    kind: str
    name: str
    file: str
    line: int
    excerpt: str
    confidence: str = "medium"
    category: str | None = None
    risk: str | None = None


RULES: dict[str, list[dict[str, str]]] = {
    "entrypoints": [
        {
            "name": "http_api",
            "pattern": r"(?i)(@(Get|Post|Put|Delete|Patch)Mapping|app\.(get|post|put|delete|patch)\(|router\.(get|post|put|delete|patch)\(|@RequestMapping|FastAPI\(|@app\.route|gin\.(GET|POST|PUT|DELETE|PATCH))",
            "risk": "medium",
        },
        {
            "name": "rpc_or_proto",
            "pattern": r"(?i)(service\s+\w+\s*\{|rpc\s+\w+\s*\(|@GrpcService|DubboService|thrift|grpc)",
            "risk": "medium",
        },
        {
            "name": "mq_consumer",
            "pattern": r"(?i)(@KafkaListener|@RabbitListener|consumer|subscribe\(|consume\(|MessageListener|topic|queue)",
            "risk": "high",
        },
        {
            "name": "scheduled_job",
            "pattern": r"(?i)(@Scheduled|cron|schedule\(|scheduler|Quartz|xxl-job|jobHandler)",
            "risk": "medium",
        },
        {
            "name": "webhook_or_callback",
            "pattern": r"(?i)(webhook|callback|notifyUrl|returnUrl|third[-_]?party)",
            "risk": "medium",
        },
    ],
    "storage": [
        {
            "name": "relational_db",
            "pattern": r"(?i)(jdbc:|DataSource|create\s+table|alter\s+table|@Entity|@Table|@Column|Repository|Mapper|SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)",
            "risk": "high",
        },
        {
            "name": "redis_or_cache",
            "pattern": r"(?i)(redis|cache|setex|get\(|hset|hmset|RedisTemplate|StringRedisTemplate)",
            "risk": "medium",
        },
        {
            "name": "search_index",
            "pattern": r"(?i)(elasticsearch|opensearch|solr|indexName|@Document)",
            "risk": "medium",
        },
        {
            "name": "object_storage",
            "pattern": r"(?i)(s3://|oss://|cos://|bucket|ObjectStorage|putObject|getObject)",
            "risk": "medium",
        },
        {
            "name": "warehouse_or_feature_store",
            "pattern": r"(?i)(warehouse|hive|spark|flink|feature[_-]?store|data[_-]?mart|bigquery|snowflake)",
            "risk": "high",
        },
    ],
    "exits": [
        {
            "name": "log_or_trace",
            "pattern": r"(?i)(logger\.(info|warn|error|debug)|console\.log|print\(|printf\(|trace|span\.setAttribute|setTag)",
            "risk": "high",
        },
        {
            "name": "mq_producer",
            "pattern": r"(?i)(send\(|publish\(|emit\(|KafkaTemplate|RabbitTemplate|producer|topic)",
            "risk": "high",
        },
        {
            "name": "api_response",
            "pattern": r"(?i)(return\s+.*(Response|Dto|VO|View)|jsonify\(|ResponseEntity|toJSON|serialize|render\()",
            "risk": "high",
        },
        {
            "name": "export_or_report",
            "pattern": r"(?i)(export|download|csv|xlsx|excel|report|dump|writeFile|OutputStream)",
            "risk": "high",
        },
        {
            "name": "sms_or_email",
            "pattern": r"(?i)(sendSms|sms|shortMessage|sendEmail|mail|email|notification)",
            "risk": "high",
        },
        {
            "name": "downstream_client",
            "pattern": r"(?i)(FeignClient|RestTemplate|WebClient|HttpClient|axios|fetch\(|requests\.|client\.)",
            "risk": "medium",
        },
    ],
}

SENSITIVE_FIELD_RULES = [
    {
        "category": "phone",
        "pattern": r"(?i)\b(phone|mobile|cellphone|telephone|tel|contactNo|receiverPhone|payerMobile|手机号|手机|电话)\b",
        "policy_hint": "tokenize_with_kms",
    },
    {
        "category": "email",
        "pattern": r"(?i)\b(email|mailAddress|e-mail|邮箱|邮件地址)\b",
        "policy_hint": "kms_encrypt",
    },
    {
        "category": "bank_card",
        "pattern": r"(?i)\b(bankCard|cardNo|cardNumber|bankAccount|accountNo|accountNumber|iban|银行卡|卡号|银行账号)\b",
        "policy_hint": "tokenize_with_kms",
    },
    {
        "category": "identity",
        "pattern": r"(?i)\b(idNo|idCard|identity|passport|nationalId|realName|fullName|姓名|身份证|证件号)\b",
        "policy_hint": "manual_confirm",
    },
    {
        "category": "credential",
        "pattern": r"(?i)\b(password|passwd|pwd|token|secret|apiKey|sessionId|otp|验证码|密码|密钥)\b",
        "policy_hint": "no_store_no_log",
    },
]

PROTECTION_RULES = [
    {"name": "tokenized", "pattern": r"(?i)(tokenize|tokenization|tokenService|detokenize|token化|令牌化)"},
    {"name": "kms_encrypted", "pattern": r"(?i)(kms|encrypt|decrypt|cipher|crypto|加密|解密)"},
    {"name": "masked", "pattern": r"(?i)(mask|masked|redact|desensiti|脱敏|隐藏)"},
]

LANGUAGE_BY_EXTENSION = {
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def fingerprint(parts: list[str]) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def is_excluded(relative_path: str, exclude_patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(relative_path) for pattern in exclude_patterns)


def iter_files(root: Path, exclude_patterns: list[re.Pattern[str]]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if is_excluded(relative, exclude_patterns):
            continue
        if path.suffix.lower() in SCAN_EXTENSIONS or path.name in {
            "Dockerfile",
            "Jenkinsfile",
            "CODEOWNERS",
            "Makefile",
        }:
            yield path


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def add_evidence(target: list[dict[str, Any]], evidence: Evidence) -> None:
    target.append(
        {
            "id": fingerprint([evidence.kind, evidence.name, evidence.file, str(evidence.line), evidence.excerpt]),
            "kind": evidence.kind,
            "name": evidence.name,
            "file": evidence.file,
            "line": evidence.line,
            "excerpt": evidence.excerpt[:500],
            "confidence": evidence.confidence,
            "category": evidence.category,
            "risk": evidence.risk,
        }
    )


def detect_repo_profile(root: Path, files: list[Path]) -> dict[str, Any]:
    manifest_names = {
        "pom.xml": "java_maven",
        "build.gradle": "java_gradle",
        "build.gradle.kts": "kotlin_gradle",
        "package.json": "node_or_frontend",
        "go.mod": "go",
        "pyproject.toml": "python",
        "requirements.txt": "python",
        "Cargo.toml": "rust",
    }
    deployment_names = {"Dockerfile", "docker-compose.yml", "Chart.yaml", "kustomization.yaml"}
    ci_names = {".gitlab-ci.yml", "Jenkinsfile", "Makefile"}

    language_counts: dict[str, int] = {}
    manifests: list[str] = []
    deployment: list[str] = []
    ci: list[str] = []
    docs: list[str] = []
    owners: list[str] = []

    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() in LANGUAGE_BY_EXTENSION:
            language = LANGUAGE_BY_EXTENSION[path.suffix.lower()]
            language_counts[language] = language_counts.get(language, 0) + 1
        if path.name in manifest_names:
            manifests.append(relative)
        if path.name in deployment_names or "/helm/" in f"/{relative}/" or "/k8s/" in f"/{relative}/":
            deployment.append(relative)
        if path.name in ci_names or relative.startswith(".github/workflows/"):
            ci.append(relative)
        if path.name.lower().startswith("readme"):
            docs.append(relative)
        if path.name == "CODEOWNERS":
            owners.append(relative)

    primary_language = max(language_counts.items(), key=lambda item: item[1])[0] if language_counts else "unknown"
    return {
        "repo_name": root.name,
        "root": str(root),
        "primary_language": primary_language,
        "language_counts": dict(sorted(language_counts.items())),
        "manifests": sorted(manifests),
        "deployment_files": sorted(deployment),
        "ci_files": sorted(ci),
        "docs": sorted(docs),
        "owner_files": sorted(owners),
    }


def infer_service_type(relative_path: str, line: str) -> str:
    haystack = f"{relative_path} {line}".lower()
    if any(word in haystack for word in ["controller", "route", "handler", "api", "server", "application"]):
        return "api"
    if any(word in haystack for word in ["consumer", "listener", "worker", "job", "scheduler"]):
        return "worker"
    if any(word in haystack for word in ["admin", "backoffice", "dashboard"]):
        return "admin"
    if any(word in haystack for word in ["pipeline", "etl", "flink", "spark"]):
        return "pipeline"
    if any(word in haystack for word in ["web", "frontend", "page", "component"]):
        return "frontend"
    return "unknown"


def detect_candidate_services(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    service_markers = [
        re.compile(r"(?i)(SpringBootApplication|public\s+static\s+void\s+main|func\s+main\(|server\.listen|FastAPI\(|Flask\(|Django|NestFactory|createApp\()"),
        re.compile(r"(?i)\b(kind:\s*(Deployment|StatefulSet|DaemonSet|CronJob)|apiVersion:\s*apps/|apiVersion:\s*batch/)\b"),
    ]

    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.name in {"Dockerfile", "package.json", "pom.xml", "go.mod"}:
            service_id = relative.rsplit("/", 1)[0] if "/" in relative else root.name
            candidates.setdefault(
                service_id,
                {
                    "id": service_id.replace("/", "-").lower(),
                    "name": service_id,
                    "type": "unknown",
                    "evidence": [],
                    "confidence": "low",
                },
            )
            add_evidence(
                candidates[service_id]["evidence"],
                Evidence("service_marker", path.name, relative, 1, f"manifest or deployment marker: {path.name}", "low"),
            )

        for line_number, line in enumerate(read_lines(path), start=1):
            if not any(marker.search(line) for marker in service_markers):
                continue
            service_id = relative.rsplit("/", 1)[0] if "/" in relative else root.name
            service_type = infer_service_type(relative, line)
            candidate = candidates.setdefault(
                service_id,
                {
                    "id": service_id.replace("/", "-").lower(),
                    "name": service_id,
                    "type": service_type,
                    "evidence": [],
                    "confidence": "medium",
                },
            )
            if candidate["type"] == "unknown":
                candidate["type"] = service_type
            candidate["confidence"] = "medium"
            add_evidence(
                candidate["evidence"],
                Evidence("service_marker", "runtime_entry", relative, line_number, line.strip(), "medium"),
            )
    return sorted(candidates.values(), key=lambda item: item["id"])


def scan_rule_group(root: Path, files: list[Path], group_name: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    compiled = [(item, re.compile(item["pattern"])) for item in RULES[group_name]]
    for path in files:
        if path.suffix.lower() == ".md":
            continue
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(read_lines(path), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for rule, pattern in compiled:
                if pattern.search(stripped):
                    add_evidence(
                        results,
                        Evidence(group_name, rule["name"], relative, line_number, stripped, "medium", risk=rule["risk"]),
                    )
    return results


def detect_protection(line: str) -> list[str]:
    protections = []
    for rule in PROTECTION_RULES:
        if re.search(rule["pattern"], line):
            protections.append(rule["name"])
    return protections


def detect_sensitive_fields(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    compiled = [(item, re.compile(item["pattern"])) for item in SENSITIVE_FIELD_RULES]
    for path in files:
        if path.suffix.lower() == ".md":
            continue
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(read_lines(path), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for rule, pattern in compiled:
                match = pattern.search(stripped)
                if not match:
                    continue
                protections = detect_protection(stripped)
                confidence = "high" if protections or path.suffix.lower() in SOURCE_EXTENSIONS else "medium"
                results.append(
                    {
                        "id": fingerprint([relative, str(line_number), rule["category"], match.group(0)]),
                        "field_hint": match.group(0),
                        "category": rule["category"],
                        "policy_hint": rule["policy_hint"],
                        "protection_hints": protections,
                        "current_state": "protected_hint_found" if protections else "unknown",
                        "confidence": confidence,
                        "file": relative,
                        "line": line_number,
                        "excerpt": stripped[:500],
                    }
                )
    return results


def build_data_flows(
    sensitive_fields: list[dict[str, Any]],
    entrypoints: list[dict[str, Any]],
    storage: list[dict[str, Any]],
    exits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    fields_by_file: dict[str, list[dict[str, Any]]] = {}
    for field in sensitive_fields:
        fields_by_file.setdefault(field["file"], []).append(field)

    contexts = {
        "entrypoints": entrypoints,
        "storage": storage,
        "exits": exits,
    }
    for file, fields in fields_by_file.items():
        related = {
            name: [item for item in items if item["file"] == file]
            for name, items in contexts.items()
        }
        if not any(related.values()):
            continue
        for field in fields:
            flow_id = fingerprint([file, field["field_hint"], field["category"]])
            flows.append(
                {
                    "id": flow_id,
                    "field_hint": field["field_hint"],
                    "category": field["category"],
                    "policy_hint": field["policy_hint"],
                    "file": file,
                    "entrypoint_refs": [item["id"] for item in related["entrypoints"]],
                    "storage_refs": [item["id"] for item in related["storage"]],
                    "exit_refs": [item["id"] for item in related["exits"]],
                    "confidence": "medium",
                    "status": "candidate_flow_needs_confirmation",
                }
            )
    return flows


def build_unknowns(
    profile: dict[str, Any],
    services: list[dict[str, Any]],
    sensitive_fields: list[dict[str, Any]],
    data_flows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unknowns: list[dict[str, Any]] = []
    if not profile["owner_files"]:
        unknowns.append(
            {
                "type": "owner_unknown",
                "reason": "No CODEOWNERS file was found. Service ownership needs confirmation.",
                "blocking": True,
            }
        )
    if not services:
        unknowns.append(
            {
                "type": "service_boundary_unknown",
                "reason": "No clear deployable service or runtime entry was detected.",
                "blocking": True,
            }
        )
    for field in sensitive_fields:
        if field["current_state"] == "unknown":
            unknowns.append(
                {
                    "type": "protection_state_unknown",
                    "reason": "Sensitive field was detected but no tokenization, KMS, encryption, or masking hint was found nearby.",
                    "field_ref": field["id"],
                    "category": field["category"],
                    "file": field["file"],
                    "line": field["line"],
                    "blocking": True,
                }
            )
    for flow in data_flows:
        if flow["exit_refs"] and flow["category"] in {"phone", "email", "bank_card"}:
            unknowns.append(
                {
                    "type": "high_risk_exit_needs_review",
                    "reason": "Core sensitive field appears in a file with an output channel.",
                    "flow_ref": flow["id"],
                    "category": flow["category"],
                    "file": flow["file"],
                    "blocking": True,
                }
            )
    return unknowns


def build_risk_summary(
    sensitive_fields: list[dict[str, Any]],
    exits: list[dict[str, Any]],
    data_flows: list[dict[str, Any]],
    unknowns: list[dict[str, Any]],
) -> dict[str, Any]:
    by_category: dict[str, int] = {}
    by_exit: dict[str, int] = {}
    for field in sensitive_fields:
        by_category[field["category"]] = by_category.get(field["category"], 0) + 1
    for exit_item in exits:
        by_exit[exit_item["name"]] = by_exit.get(exit_item["name"], 0) + 1

    high_risk_flow_count = sum(1 for flow in data_flows if flow["exit_refs"])
    blocking_unknown_count = sum(1 for item in unknowns if item.get("blocking"))
    return {
        "sensitive_field_count": len(sensitive_fields),
        "sensitive_fields_by_category": dict(sorted(by_category.items())),
        "exit_count": len(exits),
        "exits_by_type": dict(sorted(by_exit.items())),
        "candidate_data_flow_count": len(data_flows),
        "high_risk_candidate_flow_count": high_risk_flow_count,
        "blocking_unknown_count": blocking_unknown_count,
    }


def scan_repository(root: Path, exclude_patterns: list[re.Pattern[str]], exclude_values: list[str]) -> dict[str, Any]:
    files = list(iter_files(root, exclude_patterns))
    profile = detect_repo_profile(root, files)
    services = detect_candidate_services(root, files)
    entrypoints = scan_rule_group(root, files, "entrypoints")
    storage = scan_rule_group(root, files, "storage")
    exits = scan_rule_group(root, files, "exits")
    sensitive_fields = detect_sensitive_fields(root, files)
    data_flows = build_data_flows(sensitive_fields, entrypoints, storage, exits)
    unknowns = build_unknowns(profile, services, sensitive_fields, data_flows)

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": {
            "name": "repo_inventory_scanner",
            "excluded_path_patterns": exclude_values,
            "strategy": "repo_profile_service_entry_storage_exit_sensitive_field_light_flow",
        },
        "repo_profile": profile,
        "candidate_services": services,
        "entrypoints": entrypoints,
        "storage": storage,
        "exits": exits,
        "sensitive_fields": sensitive_fields,
        "data_flows": data_flows,
        "unknowns": unknowns,
        "risk_summary": build_risk_summary(sensitive_fields, exits, data_flows, unknowns),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a candidate privacy inventory from a source repository.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root to scan.")
    parser.add_argument("--output", type=Path, required=True, help="Write JSON inventory scan report to this path.")
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
        "--pretty",
        action="store_true",
        help="Print a short human-readable summary after writing JSON.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    exclude_values = [] if args.scan_toolkit else args.exclude_path
    exclude_patterns = [re.compile(value) for value in exclude_values]
    report = scan_repository(root, exclude_patterns, exclude_values)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.pretty:
        summary = report["risk_summary"]
        print(f"repo: {report['repo_profile']['repo_name']}")
        print(f"candidate services: {len(report['candidate_services'])}")
        print(f"sensitive fields: {summary['sensitive_field_count']}")
        print(f"candidate data flows: {summary['candidate_data_flow_count']}")
        print(f"blocking unknowns: {summary['blocking_unknown_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
