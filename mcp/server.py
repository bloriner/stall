#!/usr/bin/env python3
"""Stall MCP server (stdio transport, stdlib only).

Speaks MCP over newline-delimited JSON-RPC 2.0 on stdin/stdout
(no Content-Length framing), same transport style as the Terse MCP server.
Exposes a demo merchant's catalog to AI shopping agents — every listing the
agent sees has already passed through the listing firewall at load time.

v0.2: the server is stateless. All session state (carts, spend ledger,
receipts) lives in a Store backend — SQLite with an FTS5 product index by
default (STALL_DB overrides the path), STALL_STORE=memory for tests.
Checkout guardrails are enforced atomically inside the store transaction.

Security notes:
  - Totals are computed server-side from the sanitized catalog. The agent
    can never set prices.
  - Spending guardrails are enforced at checkout (per-purchase, per-merchant,
    daily caps + an approval threshold). Check and charge happen in ONE
    atomic transaction — concurrent checkouts cannot overspend.
  - Receipts are HMAC-chained and tamper-evident.
  - v0.2 has no real payment rail: checkout produces a signed *purchase
    intent* receipt. x402 settlement is future work (see README).

Run:
    python3 -m mcp.server        # from the repo root
    python3 mcp/server.py        # from the repo root
"""

from __future__ import annotations

import json
import os
import sys


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "stall-mcp"
SERVER_VERSION = "1.0.0"
AGENT_ID = "stall-demo-agent"
MAX_QTY = 99


def _ensure_repo_on_path() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)  # repo root: <repo>/mcp -> <repo>
    if root not in sys.path:
        sys.path.insert(0, root)


_ensure_repo_on_path()

from stall.guardrails import (  # noqa: E402
    GuardrailConfig,
    cents_to_str,
    sign_receipt,
)
from stall import store as store_mod  # noqa: E402


# ---------------------------------------------------------------------------
# state — everything session-scoped lives in the store, so this process is
# stateless and N servers can run behind a load balancer.
# ---------------------------------------------------------------------------

STORE = store_mod.make_store()   # SQLite file by default; STALL_DB overrides,
                                 # STALL_STORE=memory for tests/demos
GUARDRAILS = GuardrailConfig()

# The receipt-signing key. DEMO ONLY — production keys live server-side in
# the hosted service, never in the repo.
_RECEIPT_KEY = b"stall-demo-receipt-key"


def _truncate(s: str, limit: int = 500) -> str:
    return s if len(s) <= limit else s[:limit] + "..."


def error_payload(code: str, message: str) -> dict:
    """Structured error payload. Never includes a traceback."""
    return {"error": {"code": code, "message": _truncate(message)}}


# ---------------------------------------------------------------------------
# cart helpers
# ---------------------------------------------------------------------------

def _get_cart(args: dict) -> tuple[str, dict[str, int]]:
    cart_id = args.get("cart_id")
    items = STORE.get_cart(cart_id) if isinstance(cart_id, str) else None
    if items is None:
        raise KeyError("unknown cart_id")
    return cart_id, items


def _get_product_or_raise(product_id) -> dict:
    p = STORE.get_product(product_id) if isinstance(product_id, str) else None
    if p is None:
        raise KeyError("unknown product_id: %r" % (product_id,))
    return p


def _cart_summary(cart_id: str, items: dict[str, int]) -> dict:
    lines = []
    total = 0
    for pid, qty in items.items():
        p = _get_product_or_raise(pid)
        line_total = p["price_cents"] * qty
        total += line_total
        lines.append({
            "product_id": pid,
            "name": p["name"],
            "unit_price_cents": p["price_cents"],
            "currency": p["currency"],
            "qty": qty,
            "line_total_cents": line_total,
        })
    return {"cart_id": cart_id, "items": lines, "total_cents": total,
            "total": cents_to_str(total)}


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------

def tool_stall_search_products(args: dict) -> dict:
    query = args.get("query", "")
    if not isinstance(query, str):
        raise ValueError("'query' must be a string")
    category = args.get("category")
    if category is not None and not isinstance(category, str):
        raise ValueError("'category' must be a string")
    max_results = args.get("max_results", 10)
    if isinstance(max_results, bool) or not isinstance(max_results, int):
        raise ValueError("'max_results' must be an integer")
    max_results = max(1, min(50, max_results))
    results = STORE.search_products(query, category=category,
                                    max_results=max_results)
    return {"results": results, "count": len(results)}


def tool_stall_get_product(args: dict) -> dict:
    product = _get_product_or_raise(args.get("product_id"))
    return {
        "product": product,
        "firewall_report": STORE.firewall_report(product["product_id"]),
    }


def tool_stall_create_cart(args: dict) -> dict:
    return {"cart_id": STORE.create_cart()}


def tool_stall_add_to_cart(args: dict) -> dict:
    cart_id, items = _get_cart(args)
    product_id = args.get("product_id")
    _get_product_or_raise(product_id)
    qty = args.get("qty", 1)
    if isinstance(qty, bool) or not isinstance(qty, int):
        raise ValueError("'qty' must be an integer")
    if not 1 <= qty <= MAX_QTY:
        raise ValueError("'qty' must be between 1 and %d" % MAX_QTY)
    # v0.1 semantics: stored line qty is clamped at MAX_QTY
    new_qty = min(items.get(product_id, 0) + qty, MAX_QTY)
    delta = new_qty - items.get(product_id, 0)
    if delta > 0:
        STORE.add_to_cart(cart_id, product_id, delta)
    return _cart_summary(cart_id, STORE.get_cart(cart_id))


def tool_stall_get_cart(args: dict) -> dict:
    cart_id, items = _get_cart(args)
    return _cart_summary(cart_id, items)


def tool_stall_checkout(args: dict) -> dict:
    cart_id, items = _get_cart(args)
    if not items:
        return error_payload("E400", "cart is empty")
    approval = args.get("budget_approval", False)
    if not isinstance(approval, bool):
        raise ValueError("'budget_approval' must be a boolean")

    summary = _cart_summary(cart_id, items)
    total_cents = summary["total_cents"]
    merchant_id = STORE.merchant_id()

    receipt_items = [
        {
            "product_id": line["product_id"],
            "name": line["name"],
            "qty": line["qty"],
            "unit_price_cents": line["unit_price_cents"],
            "line_total_cents": line["line_total_cents"],
        }
        for line in summary["items"]
    ]

    def _build_receipt(prev_hash: str) -> dict:
        # Called INSIDE the store's atomic commit with the fresh chain
        # head, so concurrent checkouts can never fork the receipt chain.
        return sign_receipt(
            key=_RECEIPT_KEY,
            merchant_id=merchant_id,
            items=receipt_items,
            total_cents=total_cents,
            currency="USD",
            agent_id=AGENT_ID,
            prev_hash=prev_hash,
        )

    # Atomic: caps are checked, the receipt is chained, and the spend is
    # recorded in ONE transaction — concurrent checkouts cannot slip
    # between check and charge, and the chain cannot fork.
    allowed, reason, receipt = STORE.commit_purchase(
        total_cents=total_cents,
        merchant_id=merchant_id,
        config=GUARDRAILS,
        approval=approval,
        receipt_builder=_build_receipt,
    )
    if not allowed:
        return error_payload("E403", "guardrail_rejected: %s" % reason)
    STORE.delete_cart(cart_id)
    return {
        "receipt": receipt,
        "total": cents_to_str(total_cents),
        "note": "demo receipt: signed purchase intent, no real payment "
                "settled (x402 rail is future work).",
    }


def tool_stall_get_merchant(args: dict) -> dict:
    merchant_id = args.get("merchant_id", STORE.merchant_id())
    if merchant_id != STORE.merchant_id():
        raise KeyError("unknown merchant_id: %r" % (merchant_id,))
    m = STORE.merchant()
    return {
        "merchant_id": m["merchant_id"],
        "name": m["name"],
        "since": m["since"],
        "description": m.get("description", ""),
        "trust": STORE.firewall_stats(),
    }


TOOLS = {
    "stall_search_products": {
        "fn": tool_stall_search_products,
        "description": (
            "Search the merchant catalog. Returns sanitized listings only — "
            "every listing has passed through the prompt-injection firewall, "
            "and each result flags whether its merchant signature verified."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "description": "Search text (matches name, category, attributes, description)."},
                "category": {"type": "string",
                             "description": "Optional category filter."},
                "max_results": {"type": "integer", "default": 10,
                                "minimum": 1, "maximum": 50},
            },
            "required": ["query"],
        },
    },
    "stall_get_product": {
        "fn": tool_stall_get_product,
        "description": (
            "Full detail for one product, firewall-sanitized, with its "
            "firewall_report (what was stripped, signature valid/invalid)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {"type": "string",
                               "description": "Product ID from search results."},
            },
            "required": ["product_id"],
        },
    },
    "stall_create_cart": {
        "fn": tool_stall_create_cart,
        "description": "Create an empty cart. Returns a cart_id.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "stall_add_to_cart": {
        "fn": tool_stall_add_to_cart,
        "description": "Add a product to a cart. Prices come from the sanitized catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cart_id": {"type": "string"},
                "product_id": {"type": "string"},
                "qty": {"type": "integer", "default": 1, "minimum": 1, "maximum": 99},
            },
            "required": ["cart_id", "product_id"],
        },
    },
    "stall_get_cart": {
        "fn": tool_stall_get_cart,
        "description": "Show cart contents with server-computed totals.",
        "inputSchema": {
            "type": "object",
            "properties": {"cart_id": {"type": "string"}},
            "required": ["cart_id"],
        },
    },
    "stall_checkout": {
        "fn": tool_stall_checkout,
        "description": (
            "Checkout a cart. Spending guardrails are enforced server-side "
            "(per-purchase / per-merchant / daily caps, approval threshold). "
            "Returns a signed, tamper-evident receipt, or a guardrail rejection "
            "with the exact reason. v0.1 settles no real payment."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cart_id": {"type": "string"},
                "budget_approval": {
                    "type": "boolean", "default": False,
                    "description": "Set true to approve purchases above the approval threshold.",
                },
            },
            "required": ["cart_id"],
        },
    },
    "stall_get_merchant": {
        "fn": tool_stall_get_merchant,
        "description": "Merchant info plus firewall trust signals for its catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "merchant_id": {"type": "string",
                                "description": "Defaults to the demo merchant."},
            },
        },
    },
}


# ---------------------------------------------------------------------------
# JSON-RPC dispatch (same shape as the Terse MCP server)
# ---------------------------------------------------------------------------

def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, args: dict) -> dict:
    try:
        tool = TOOLS.get(name)
        if tool is None:
            raise KeyError("unknown tool: %s" % name)
        if not isinstance(args, dict):
            args = {}
        payload = tool["fn"](args)
    except (ValueError, KeyError) as exc:
        return {
            "content": [{"type": "text", "text": json.dumps(
                error_payload("E400", str(exc)))}],
            "isError": True,
        }
    except Exception as exc:  # never leak tracebacks
        return {
            "content": [{"type": "text", "text": json.dumps(
                error_payload("E999", "%s: %s" % (
                    type(exc).__name__, _truncate(str(exc) or "unknown"))))}],
            "isError": True,
        }
    text = json.dumps(payload)
    result = {"content": [{"type": "text", "text": text}]}
    if isinstance(payload, dict) and "error" in payload:
        result["isError"] = True
    return result


def handle(msg: dict):
    """Return a JSON-RPC response dict, or None for notifications."""
    if not isinstance(msg, dict):
        # No addressable id — log and drop.
        print("invalid JSON-RPC message (not an object)", file=sys.stderr)
        return None
    if msg.get("jsonrpc") != "2.0" or "method" not in msg:
        if "id" in msg:
            return _err(msg.get("id"), -32600, "Invalid Request")
        return None
    method = msg["method"]
    msg_id = msg.get("id")
    if "id" not in msg:
        # Notification: never respond (JSON-RPC 2.0). The server is
        # stateless, so notifications carry no side effects either.
        return None

    if method == "initialize":
        return _ok(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "ping":
        return _ok(msg_id, {})
    if method == "tools/list":
        tools = [
            {"name": name, "description": t["description"],
             "inputSchema": t["inputSchema"]}
            for name, t in TOOLS.items()
        ]
        return _ok(msg_id, {"tools": tools})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        return _ok(msg_id, _call_tool(name, args))
    return _err(msg_id, -32601, "Method not found: %s" % method)


def serve() -> None:
    stdin = sys.stdin
    stdout = sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            print("invalid JSON-RPC line: %s" % exc, file=sys.stderr)
            stdout.write(json.dumps(
                _err(None, -32700, "Parse error")) + "\n")
            stdout.flush()
            continue
        try:
            resp = handle(msg)
        except Exception as exc:  # absolute last resort; never crash the loop
            print("handler crashed: %r" % exc, file=sys.stderr)
            continue
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
