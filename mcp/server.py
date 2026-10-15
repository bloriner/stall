#!/usr/bin/env python3
"""Stall MCP server (stdio transport, stdlib only).

Speaks MCP over newline-delimited JSON-RPC 2.0 on stdin/stdout
(no Content-Length framing), same transport style as the Terse MCP server.
Exposes a demo merchant's catalog to AI shopping agents — every listing the
agent sees has already passed through the listing firewall at load time.

Security notes:
  - Totals are computed server-side from the sanitized catalog. The agent
    can never set prices.
  - Spending guardrails are enforced at checkout (per-purchase, per-merchant,
    daily caps + an approval threshold).
  - Receipts are HMAC-chained and tamper-evident.
  - v0.1 has no real payment rail: checkout produces a signed *purchase
    intent* receipt. x402 settlement is future work (see README).

Run:
    python3 -m mcp.server        # from the repo root
    python3 mcp/server.py        # from the repo root
"""

from __future__ import annotations

import json
import os
import sys
import uuid

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "stall-mcp"
SERVER_VERSION = "0.1.0"
AGENT_ID = "stall-demo-agent"
MAX_QTY = 99


def _ensure_repo_on_path() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)  # repo root: <repo>/mcp -> <repo>
    if root not in sys.path:
        sys.path.insert(0, root)


_ensure_repo_on_path()

from stall import catalog as catalog_mod  # noqa: E402
from stall import guardrails  # noqa: E402
from stall.guardrails import (  # noqa: E402
    GuardrailConfig,
    GuardrailState,
    cents_to_str,
    receipt_hash,
    sign_receipt,
    verify_chain,
    GENESIS_HASH,
)


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

CATALOG = catalog_mod.load_demo()
GUARDRAILS = GuardrailConfig()
SPEND = GuardrailState()
CARTS: dict[str, dict[str, int]] = {}          # cart_id -> {product_id: qty}
RECEIPTS: list[dict] = []                      # HMAC-chained receipts
_LAST_HASH = GENESIS_HASH

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
    if not isinstance(cart_id, str) or cart_id not in CARTS:
        raise KeyError("unknown cart_id")
    return cart_id, CARTS[cart_id]


def _cart_summary(cart_id: str, items: dict[str, int]) -> dict:
    lines = []
    total = 0
    for pid, qty in items.items():
        p = CATALOG.products[pid]
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
    results = CATALOG.search(query, category=category, max_results=max_results)
    return {"results": results, "count": len(results)}


def tool_stall_get_product(args: dict) -> dict:
    product_id = args.get("product_id")
    if not isinstance(product_id, str) or product_id not in CATALOG.products:
        raise KeyError("unknown product_id: %r" % (product_id,))
    return {
        "product": CATALOG.products[product_id],
        "firewall_report": CATALOG.reports[product_id],
    }


def tool_stall_create_cart(args: dict) -> dict:
    cart_id = uuid.uuid4().hex
    CARTS[cart_id] = {}
    return {"cart_id": cart_id}


def tool_stall_add_to_cart(args: dict) -> dict:
    cart_id, items = _get_cart(args)
    product_id = args.get("product_id")
    if not isinstance(product_id, str) or product_id not in CATALOG.products:
        raise KeyError("unknown product_id: %r" % (product_id,))
    qty = args.get("qty", 1)
    if isinstance(qty, bool) or not isinstance(qty, int):
        raise ValueError("'qty' must be an integer")
    if not 1 <= qty <= MAX_QTY:
        raise ValueError("'qty' must be between 1 and %d" % MAX_QTY)
    items[product_id] = items.get(product_id, 0) + qty
    if items[product_id] > MAX_QTY:
        items[product_id] = MAX_QTY
    return _cart_summary(cart_id, items)


def tool_stall_get_cart(args: dict) -> dict:
    cart_id, items = _get_cart(args)
    return _cart_summary(cart_id, items)


def tool_stall_checkout(args: dict) -> dict:
    global _LAST_HASH
    cart_id, items = _get_cart(args)
    if not items:
        return error_payload("E400", "cart is empty")
    approval = args.get("budget_approval", False)
    if not isinstance(approval, bool):
        raise ValueError("'budget_approval' must be a boolean")

    summary = _cart_summary(cart_id, items)
    total_cents = summary["total_cents"]
    merchant_id = CATALOG.merchant_id

    allowed, reason = SPEND.evaluate(
        total_cents, merchant_id, GUARDRAILS, approval=approval
    )
    if not allowed:
        return error_payload("E403", "guardrail_rejected: %s" % reason)

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
    receipt = sign_receipt(
        key=_RECEIPT_KEY,
        merchant_id=merchant_id,
        items=receipt_items,
        total_cents=total_cents,
        currency="USD",
        agent_id=AGENT_ID,
        prev_hash=_LAST_HASH,
    )
    _LAST_HASH = receipt_hash(receipt)
    RECEIPTS.append(receipt)
    SPEND.record(total_cents, merchant_id)
    del CARTS[cart_id]
    return {
        "receipt": receipt,
        "total": cents_to_str(total_cents),
        "note": "v0.1 demo receipt: signed purchase intent, no real payment "
                "settled (x402 rail is future work).",
    }


def tool_stall_get_merchant(args: dict) -> dict:
    merchant_id = args.get("merchant_id", CATALOG.merchant_id)
    if merchant_id != CATALOG.merchant_id:
        raise KeyError("unknown merchant_id: %r" % (merchant_id,))
    m = CATALOG.merchant
    return {
        "merchant_id": m["merchant_id"],
        "name": m["name"],
        "since": m["since"],
        "description": m.get("description", ""),
        "trust": CATALOG.firewall_stats(),
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
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        return None
    method = msg["method"]
    msg_id = msg.get("id")
    is_notification = "id" not in msg

    if method == "initialize":
        return _ok(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "notifications/initialized":
        return None
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
        if is_notification:
            return None
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        return _ok(msg_id, _call_tool(name, args))
    if is_notification:
        return None
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
