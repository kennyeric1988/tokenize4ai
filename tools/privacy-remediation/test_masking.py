#!/usr/bin/env python3
"""Smoke tests for masking helpers.

Run with:
    python3 tools/privacy-remediation/test_masking.py
"""

from masking import (
    REDACTED,
    detect_and_redact_free_text,
    keyed_hash,
    mask_email,
    mask_ipv4,
    mask_phone,
    mask_record,
)


def test_masking_helpers() -> None:
    assert mask_email("alice@example.com") == "a***@example.com"
    assert mask_phone("+1 (555) 123-4567") == "*******4567"
    assert mask_ipv4("192.168.1.10") == "192.168.*.*"
    assert keyed_hash("user-123", "secret") == keyed_hash("user-123", "secret")
    assert keyed_hash("user-123", "secret") != keyed_hash("user-456", "secret")

    text = "email alice@example.com phone +1 555 123 4567 token abcdefghijklmnopqrstuvwxyz"
    redacted = detect_and_redact_free_text(text)
    assert "alice@example.com" not in redacted
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert REDACTED in redacted

    record = {
        "email": "alice@example.com",
        "token": "abcdefghijklmnopqrstuvwxyz",
        "note": "call +1 555 123 4567",
    }
    masked = mask_record(
        record,
        {
            "email": "partial_mask",
            "token": "no_store_no_log",
            "note": "detect_and_redact",
        },
    )
    assert masked["email"] == "a***@example.com"
    assert masked["token"] == REDACTED
    assert "555" not in masked["note"]


if __name__ == "__main__":
    test_masking_helpers()
    print("masking helper smoke tests passed")
