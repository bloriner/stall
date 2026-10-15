#!/usr/bin/env python3
"""Guardrail + receipt tests: caps must fire with exact reasons, receipts
must verify, and any tampering must break the chain."""

import unittest

from stall.guardrails import (
    GuardrailConfig,
    GuardrailState,
    cents_to_str,
    sign_receipt,
    verify_receipt,
    verify_chain,
    receipt_hash,
    GENESIS_HASH,
)

KEY = b"test-receipt-key"


def _receipt(total_cents=1000, prev_hash=GENESIS_HASH, **over):
    kw = dict(
        key=KEY,
        merchant_id="m1",
        items=[{"product_id": "p1", "qty": 1, "unit_price_cents": total_cents,
                "line_total_cents": total_cents}],
        total_cents=total_cents,
        currency="USD",
        agent_id="agent-1",
        prev_hash=prev_hash,
    )
    kw.update(over)
    return sign_receipt(**kw)


class TestGuardrails(unittest.TestCase):
    def setUp(self):
        self.cfg = GuardrailConfig(
            max_per_purchase_cents=50_000,
            max_per_merchant_cents=200_000,
            max_daily_cents=500_000,
            approval_threshold_cents=10_000,
        )
        self.state = GuardrailState()

    def test_small_purchase_allowed(self):
        ok, reason = self.state.evaluate(5_000, "m1", self.cfg)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_per_purchase_cap(self):
        ok, reason = self.state.evaluate(60_000, "m1", self.cfg, approval=True)
        self.assertFalse(ok)
        self.assertIn("per-purchase cap", reason)
        self.assertIn("$600.00", reason)
        self.assertIn("$500.00", reason)

    def test_per_merchant_cap_accumulates(self):
        self.state.record(170_000, "m1")
        ok, reason = self.state.evaluate(40_000, "m1", self.cfg, approval=True)
        self.assertFalse(ok)
        self.assertIn("per-merchant cap", reason)

    def test_daily_cap(self):
        self.state.record(490_000, "m1")
        ok, reason = self.state.evaluate(20_000, "m2", self.cfg, approval=True)
        self.assertFalse(ok)
        self.assertIn("daily cap", reason)

    def test_approval_threshold_requires_flag(self):
        ok, reason = self.state.evaluate(15_000, "m1", self.cfg, approval=False)
        self.assertFalse(ok)
        self.assertIn("requires explicit approval", reason)
        ok2, _ = self.state.evaluate(15_000, "m1", self.cfg, approval=True)
        self.assertTrue(ok2)

    def test_below_threshold_no_approval_needed(self):
        ok, _ = self.state.evaluate(9_999, "m1", self.cfg, approval=False)
        self.assertTrue(ok)

    def test_zero_total_rejected(self):
        ok, reason = self.state.evaluate(0, "m1", self.cfg)
        self.assertFalse(ok)

    def test_cents_to_str(self):
        self.assertEqual(cents_to_str(1), "$0.01")
        self.assertEqual(cents_to_str(50_000), "$500.00")


class TestReceipts(unittest.TestCase):
    def test_receipt_verifies(self):
        r = _receipt()
        self.assertTrue(verify_receipt(r, KEY))

    def test_wrong_key_fails(self):
        r = _receipt()
        self.assertFalse(verify_receipt(r, b"other-key"))

    def test_tampered_total_fails(self):
        r = _receipt(total_cents=1000)
        r["total_cents"] = 1
        self.assertFalse(verify_receipt(r, KEY))

    def test_tampered_item_fails(self):
        r = _receipt()
        r["items"][0]["qty"] = 999
        self.assertFalse(verify_receipt(r, KEY))

    def test_missing_hmac_fails(self):
        r = _receipt()
        del r["hmac"]
        self.assertFalse(verify_receipt(r, KEY))

    def test_chain_verifies(self):
        r1 = _receipt(receipt_id="r1")
        r2 = _receipt(receipt_id="r2", prev_hash=receipt_hash(r1))
        r3 = _receipt(receipt_id="r3", prev_hash=receipt_hash(r2))
        ok, reason = verify_chain([r1, r2, r3], KEY)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_chain_break_detected(self):
        r1 = _receipt(receipt_id="r1")
        r2 = _receipt(receipt_id="r2", prev_hash="tampered-prev")
        # re-sign r2 so its own HMAC is valid but the link is broken
        ok, reason = verify_chain([r1, r2], KEY)
        self.assertFalse(ok)
        self.assertIn("chain", reason)

    def test_chain_tamper_in_middle_detected(self):
        r1 = _receipt(receipt_id="r1")
        r2 = _receipt(receipt_id="r2", prev_hash=receipt_hash(r1))
        r2["total_cents"] = 5  # tamper after signing
        r3 = _receipt(receipt_id="r3", prev_hash=receipt_hash(r2))
        ok, reason = verify_chain([r1, r2, r3], KEY)
        self.assertFalse(ok)
        self.assertIn("invalid HMAC", reason)

    def test_empty_chain_ok(self):
        ok, reason = verify_chain([], KEY)
        self.assertTrue(ok)
        self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
