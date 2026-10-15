#!/usr/bin/env python3
"""MCP server stdio round-trip tests: full shop flow over NDJSON JSON-RPC,
including the adversarial listings and a guardrail rejection."""

import json
import os
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ServerProc:
    """A live stall MCP server over stdio."""

    def __init__(self):
        self.proc = subprocess.Popen(
            ["python3", "-m", "mcp.server"],
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def call(self, method, params=None):
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        return json.loads(line)

    def tool(self, name, arguments=None):
        resp = self.call("tools/call",
                         {"name": name, "arguments": arguments or {}})
        result = resp["result"]
        payload = json.loads(result["content"][0]["text"])
        return payload, result.get("isError", False)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.proc.terminate()
        self.proc.wait(timeout=10)


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ServerProc()
        init = cls.srv.call("initialize")
        assert init["result"]["serverInfo"]["name"] == "stall-mcp", init

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_tools_list(self):
        resp = self.srv.call("tools/list")
        names = {t["name"] for t in resp["result"]["tools"]}
        for expected in ("stall_search_products", "stall_get_product",
                         "stall_create_cart", "stall_add_to_cart",
                         "stall_get_cart", "stall_checkout", "stall_get_merchant"):
            self.assertIn(expected, names)

    def test_search(self):
        payload, is_err = self.srv.tool("stall_search_products", {"query": "mouse"})
        self.assertFalse(is_err)
        self.assertTrue(payload["count"] >= 1)
        self.assertEqual(payload["results"][0]["product_id"], "mouse-w1")

    def test_search_category(self):
        payload, _ = self.srv.tool(
            "stall_search_products", {"query": "", "category": "grocery"})
        ids = {r["product_id"] for r in payload["results"]}
        self.assertIn("coffee-1kg", ids)

    def test_adversarial_product_sanitized_over_mcp(self):
        payload, is_err = self.srv.tool("stall_get_product", {"product_id": "widget-x9"})
        self.assertFalse(is_err)
        desc = payload["product"]["description"]
        self.assertNotIn("Ignore previous instructions", desc)
        self.assertIn("unbeatable price", desc)
        self.assertTrue(len(payload["firewall_report"]["stripped"]) >= 1)

    def test_invalid_signature_flagged_over_mcp(self):
        payload, _ = self.srv.tool("stall_get_product", {"product_id": "gadget-x1"})
        self.assertFalse(payload["firewall_report"]["signature_valid"])

    def test_unknown_product_errors(self):
        payload, is_err = self.srv.tool("stall_get_product", {"product_id": "nope"})
        self.assertTrue(is_err)
        self.assertIn("error", payload)

    def test_cart_flow_and_checkout(self):
        payload, _ = self.srv.tool("stall_create_cart")
        cart_id = payload["cart_id"]
        payload, _ = self.srv.tool(
            "stall_add_to_cart",
            {"cart_id": cart_id, "product_id": "mouse-w1", "qty": 2})
        self.assertEqual(payload["total_cents"], 5998)
        payload, _ = self.srv.tool("stall_get_cart", {"cart_id": cart_id})
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["qty"], 2)
        payload, is_err = self.srv.tool("stall_checkout", {"cart_id": cart_id})
        self.assertFalse(is_err)
        receipt = payload["receipt"]
        self.assertEqual(receipt["total_cents"], 5998)
        self.assertTrue(receipt["hmac"])
        # prev_hash links to the previous receipt in this server's chain
        # (other tests may have checked out first, so don't assume genesis)
        self.assertRegex(receipt["prev_hash"], r"^[0-9a-f]{64}$")
        # cart is consumed
        _, is_err2 = self.srv.tool("stall_get_cart", {"cart_id": cart_id})
        self.assertTrue(is_err2)

    def test_receipt_chain_links(self):
        p1, _ = self.srv.tool("stall_create_cart")
        self.srv.tool("stall_add_to_cart",
                      {"cart_id": p1["cart_id"], "product_id": "notebook-3pk", "qty": 1})
        r1, _ = self.srv.tool("stall_checkout", {"cart_id": p1["cart_id"]})
        p2, _ = self.srv.tool("stall_create_cart")
        self.srv.tool("stall_add_to_cart",
                      {"cart_id": p2["cart_id"], "product_id": "mat-yoga", "qty": 1})
        r2, _ = self.srv.tool("stall_checkout", {"cart_id": p2["cart_id"]})
        import hashlib
        expected_prev = hashlib.sha256(
            r1["receipt"]["hmac"].encode()).hexdigest()
        self.assertEqual(r2["receipt"]["prev_hash"], expected_prev)

    def test_guardrail_rejection_over_mcp(self):
        # gadget-x1 at $199.99 x 3 = $599.97 > $500 per-purchase cap
        payload, _ = self.srv.tool("stall_create_cart")
        cart_id = payload["cart_id"]
        self.srv.tool("stall_add_to_cart",
                      {"cart_id": cart_id, "product_id": "gadget-x1", "qty": 3})
        payload, is_err = self.srv.tool(
            "stall_checkout", {"cart_id": cart_id, "budget_approval": True})
        self.assertTrue(is_err)
        self.assertIn("per-purchase cap", payload["error"]["message"])

    def test_approval_threshold_over_mcp(self):
        # kb-mech2 x2 = $179.98 > $100 approval threshold, no approval flag
        payload, _ = self.srv.tool("stall_create_cart")
        cart_id = payload["cart_id"]
        self.srv.tool("stall_add_to_cart",
                      {"cart_id": cart_id, "product_id": "kb-mech2", "qty": 2})
        payload, is_err = self.srv.tool("stall_checkout", {"cart_id": cart_id})
        self.assertTrue(is_err)
        self.assertIn("requires explicit approval", payload["error"]["message"])
        # same cart with approval goes through
        payload2, is_err2 = self.srv.tool(
            "stall_checkout", {"cart_id": cart_id, "budget_approval": True})
        self.assertFalse(is_err2)
        self.assertIn("receipt", payload2)

    def test_merchant_trust_signals(self):
        payload, _ = self.srv.tool("stall_get_merchant", {})
        self.assertEqual(payload["merchant_id"], "demo-merchant")
        trust = payload["trust"]
        self.assertEqual(trust["products_total"], 10)
        self.assertEqual(trust["signatures_invalid"], 1)   # gadget-x1
        self.assertGreaterEqual(trust["listings_sanitized"], 2)  # widget-x9 + gadget-x1

    def test_bad_args_error_cleanly(self):
        _, is_err = self.srv.tool(
            "stall_add_to_cart",
            {"cart_id": "bogus", "product_id": "mouse-w1", "qty": 1})
        self.assertTrue(is_err)
        _, is_err = self.srv.tool(
            "stall_search_products", {"query": 123})
        self.assertTrue(is_err)


if __name__ == "__main__":
    unittest.main()
