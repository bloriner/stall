#!/usr/bin/env python3
"""Stall spending guardrails + tamper-evident receipts.

Two jobs:

1. Guardrails — the shopper's agent cannot spend beyond configured limits,
   no matter what a merchant listing says. Caps are checked server-side at
   checkout against totals the server computed itself (never client-supplied
   prices).

2. Receipts — every completed purchase produces a signed receipt chained to
   the previous one (hash-linked, HMAC-SHA256). Tampering with any receipt
   breaks the chain. This is the paper trail for disputes and the audit log
   for the shopper.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import date, datetime, timezone


def cents_to_str(cents: int) -> str:
    return "$%.2f" % (cents / 100)


class GuardrailConfig:
    """Spending limits, all in integer cents."""

    def __init__(
        self,
        max_per_purchase_cents: int = 50_000,    # $500 per checkout
        max_per_merchant_cents: int = 200_000,   # $2,000 lifetime per merchant
        max_daily_cents: int = 500_000,          # $5,000 per day
        approval_threshold_cents: int = 10_000,  # above $100 needs explicit approval
    ) -> None:
        for name, v in (
            ("max_per_purchase_cents", max_per_purchase_cents),
            ("max_per_merchant_cents", max_per_merchant_cents),
            ("max_daily_cents", max_daily_cents),
            ("approval_threshold_cents", approval_threshold_cents),
        ):
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError("%s must be a non-negative integer" % name)
        self.max_per_purchase_cents = max_per_purchase_cents
        self.max_per_merchant_cents = max_per_merchant_cents
        self.max_daily_cents = max_daily_cents
        self.approval_threshold_cents = approval_threshold_cents

    def to_dict(self) -> dict:
        return {
            "max_per_purchase_cents": self.max_per_purchase_cents,
            "max_per_merchant_cents": self.max_per_merchant_cents,
            "max_daily_cents": self.max_daily_cents,
            "approval_threshold_cents": self.approval_threshold_cents,
        }


class GuardrailState:
    """Tracks spend against the caps. In-memory for v0.1."""

    def __init__(self) -> None:
        self.per_merchant_cents: dict[str, int] = {}
        self.daily_cents: dict[str, int] = {}  # "YYYY-MM-DD" -> cents

    def _today(self) -> str:
        return date.today().isoformat()

    def evaluate(
        self,
        total_cents: int,
        merchant_id: str,
        config: GuardrailConfig,
        approval: bool = False,
    ) -> tuple[bool, str | None]:
        """Check a prospective purchase. Returns (allowed, reason).

        `reason` is None when allowed, otherwise an exact human-readable
        explanation of which cap fired.
        """
        if total_cents <= 0:
            return False, "cart total must be positive"
        if total_cents > config.max_per_purchase_cents:
            return (
                False,
                "exceeds per-purchase cap: %s > %s limit"
                % (cents_to_str(total_cents),
                   cents_to_str(config.max_per_purchase_cents)),
            )
        merchant_spend = self.per_merchant_cents.get(merchant_id, 0)
        if merchant_spend + total_cents > config.max_per_merchant_cents:
            return (
                False,
                "exceeds per-merchant cap: %s already spent with this merchant, "
                "+ %s would pass the %s limit"
                % (
                    cents_to_str(merchant_spend),
                    cents_to_str(total_cents),
                    cents_to_str(config.max_per_merchant_cents),
                ),
            )
        today = self._today()
        day_spend = self.daily_cents.get(today, 0)
        if day_spend + total_cents > config.max_daily_cents:
            return (
                False,
                "exceeds daily cap: %s already spent today, + %s would pass "
                "the %s limit"
                % (
                    cents_to_str(day_spend),
                    cents_to_str(total_cents),
                    cents_to_str(config.max_daily_cents),
                ),
            )
        if total_cents > config.approval_threshold_cents and not approval:
            return (
                False,
                "requires explicit approval: %s exceeds the %s "
                "approval threshold (pass budget_approval=true)"
                % (
                    cents_to_str(total_cents),
                    cents_to_str(config.approval_threshold_cents),
                ),
            )
        return True, None

    def record(self, total_cents: int, merchant_id: str) -> None:
        self.per_merchant_cents[merchant_id] = (
            self.per_merchant_cents.get(merchant_id, 0) + total_cents
        )
        today = self._today()
        self.daily_cents[today] = self.daily_cents.get(today, 0) + total_cents


# ---------------------------------------------------------------------------
# receipts: HMAC-chained, tamper-evident
# ---------------------------------------------------------------------------

GENESIS_HASH = "0" * 64


def _canonical_receipt_body(receipt: dict) -> bytes:
    body = {k: v for k, v in receipt.items() if k != "hmac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_receipt(
    *,
    key: bytes,
    merchant_id: str,
    items: list[dict],
    total_cents: int,
    currency: str,
    agent_id: str,
    prev_hash: str,
    receipt_id: str | None = None,
    timestamp: str | None = None,
) -> dict:
    """Create a signed receipt chained to the previous receipt's hash."""
    import uuid as _uuid

    receipt = {
        "receipt_id": receipt_id or _uuid.uuid4().hex,
        "timestamp": timestamp
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "merchant_id": merchant_id,
        "agent_id": agent_id,
        "items": items,
        "total_cents": total_cents,
        "currency": currency,
        "prev_hash": prev_hash,
    }
    receipt["hmac"] = hmac.new(
        key, _canonical_receipt_body(receipt), hashlib.sha256
    ).hexdigest()
    return receipt


def verify_receipt(receipt: dict, key: bytes) -> bool:
    """True iff the receipt's HMAC is valid for its contents."""
    sig = receipt.get("hmac")
    if not isinstance(sig, str) or not sig:
        return False
    expected = hmac.new(
        key, _canonical_receipt_body(receipt), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


def verify_chain(receipts: list[dict], key: bytes) -> tuple[bool, str | None]:
    """Verify a whole receipt chain. Returns (ok, reason)."""
    prev = GENESIS_HASH
    for i, r in enumerate(receipts):
        if not verify_receipt(r, key):
            return False, "receipt %d (%s) has an invalid HMAC" % (
                i, r.get("receipt_id", "?"))
        if r.get("prev_hash") != prev:
            return False, "receipt %d (%s) breaks the chain: prev_hash mismatch" % (
                i, r.get("receipt_id", "?"))
        prev = receipt_hash(r)
    return True, None


def receipt_hash(receipt: dict) -> str:
    """The chain link: hash of a verified receipt's HMAC."""
    return hashlib.sha256(receipt["hmac"].encode("utf-8")).hexdigest()
