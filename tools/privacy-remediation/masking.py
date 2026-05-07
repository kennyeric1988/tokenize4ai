#!/usr/bin/env python3
"""Reusable masking helpers for remediation prototypes and tests."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any


REDACTED = "[REDACTED]"
EMAIL_RE = re.compile(r"(?P<local>[^@\s]{1,64})@(?P<domain>[^@\s]+\.[^@\s]+)")
PHONE_RE = re.compile(r"\+?[0-9][0-9\s().-]{6,}[0-9]")
IPV4_RE = re.compile(r"\b(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3})\b")
TOKEN_RE = re.compile(r"(?i)\b(bearer\s+)?[a-z0-9_-]{24,}\b")


def redact(value: Any) -> str | None:
    """Fully redact a present value while preserving null semantics."""
    if value is None:
        return None
    return REDACTED


def mask_email(value: str | None) -> str | None:
    if value is None:
        return None
    match = EMAIL_RE.fullmatch(value.strip())
    if not match:
        return REDACTED
    local = match.group("local")
    domain = match.group("domain")
    visible = local[0] if local else "*"
    return f"{visible}***@{domain}"


def mask_phone(value: str | None, visible_digits: int = 4) -> str | None:
    if value is None:
        return None
    digits = re.sub(r"\D", "", value)
    if not digits:
        return REDACTED
    suffix = digits[-visible_digits:]
    return f"{'*' * max(len(digits) - len(suffix), 0)}{suffix}"


def mask_ipv4(value: str | None) -> str | None:
    if value is None:
        return None
    match = IPV4_RE.fullmatch(value.strip())
    if not match:
        return REDACTED
    return f"{match.group('a')}.{match.group('b')}.*.*"


def keyed_hash(value: str | None, secret: str, prefix: str = "tok") -> str | None:
    """Create a deterministic token with a secret key for small-domain values."""
    if value is None:
        return None
    digest = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}_{digest[:24]}"


def detect_and_redact_free_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = EMAIL_RE.sub(lambda _: REDACTED, value)
    value = PHONE_RE.sub(lambda _: REDACTED, value)
    value = IPV4_RE.sub(lambda _: REDACTED, value)
    value = TOKEN_RE.sub(lambda _: REDACTED, value)
    return value


def mask_by_policy(value: Any, policy: str, *, field_name: str = "", hash_secret: str | None = None) -> Any:
    """Apply a policy using conservative defaults for generated remediation tests."""
    if policy == "redact" or policy == "no_store_no_log":
        return redact(value)
    if policy == "detect_and_redact":
        return detect_and_redact_free_text(None if value is None else str(value))
    if policy == "tokenize_or_hash":
        if not hash_secret:
            raise ValueError("hash_secret is required for tokenize_or_hash")
        return keyed_hash(None if value is None else str(value), hash_secret)
    if policy == "partial_mask":
        text = None if value is None else str(value)
        normalized_field = field_name.lower()
        if "email" in normalized_field:
            return mask_email(text)
        if "phone" in normalized_field or "mobile" in normalized_field:
            return mask_phone(text)
        if "ip" in normalized_field:
            return mask_ipv4(text)
        return redact(value)
    if policy == "aggregate_or_minimize":
        return redact(value)
    if policy == "access_controlled_reveal":
        return redact(value)
    raise ValueError(f"Unknown masking policy: {policy}")


def mask_record(record: dict[str, Any], policy_by_field: dict[str, str], *, hash_secret: str | None = None) -> dict[str, Any]:
    masked = dict(record)
    for field_name, policy in policy_by_field.items():
        if field_name in masked:
            masked[field_name] = mask_by_policy(masked[field_name], policy, field_name=field_name, hash_secret=hash_secret)
    return masked
