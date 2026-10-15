#!/usr/bin/env python3
"""Stall catalog loading. The firewall is applied at load time: the in-memory
catalog only ever holds sanitized listings, plus each listing's firewall
report. Raw merchant text never reaches the MCP tools.
"""

from __future__ import annotations

import json
import os

from . import firewall

_HERE = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.normpath(os.path.join(_HERE, "..", "demo"))


class Catalog:
    def __init__(self, merchant: dict, products: dict[str, dict],
                 reports: dict[str, dict], merchant_key: bytes) -> None:
        self.merchant = merchant
        self.products = products          # product_id -> sanitized product
        self.reports = reports            # product_id -> firewall report
        self.merchant_key = merchant_key

    @property
    def merchant_id(self) -> str:
        return self.merchant["merchant_id"]

    def search(self, query: str, category: str | None = None,
               max_results: int = 10) -> list[dict]:
        tokens = [t for t in query.lower().split() if t]
        hits: list[tuple[int, dict]] = []
        for pid, p in self.products.items():
            if category and p["category"].lower() != category.lower():
                continue
            hay = " ".join([
                p["name"], p["category"], p["description"],
                *[str(v) for v in p["attributes"].values()],
            ]).lower()
            score = sum(1 for t in tokens if t in hay)
            if score or not tokens:
                hits.append((score, p))
        hits.sort(key=lambda h: (-h[0], h[1]["name"]))
        return [self.summary(p) for _, p in hits[:max_results]]

    def summary(self, p: dict) -> dict:
        return {
            "product_id": p["product_id"],
            "name": p["name"],
            "price_cents": p["price_cents"],
            "currency": p["currency"],
            "category": p["category"],
            "signature_valid": self.reports[p["product_id"]]["signature_valid"],
        }

    def firewall_stats(self) -> dict:
        total = len(self.reports)
        valid = sum(1 for r in self.reports.values() if r["signature_valid"])
        sanitized = sum(1 for r in self.reports.values() if r["sanitized"])
        return {
            "products_total": total,
            "signatures_valid": valid,
            "signatures_invalid": total - valid,
            "listings_sanitized": sanitized,
        }


def _read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_demo(demo_dir: str = DEMO_DIR) -> Catalog:
    """Load the demo merchant, firewalling every listing at load."""
    merchant = _read_json(os.path.join(demo_dir, "merchant.json"))
    raw_products = _read_json(os.path.join(demo_dir, "products.json"))
    key = merchant["hmac_key"].encode("utf-8")
    products: dict[str, dict] = {}
    reports: dict[str, dict] = {}
    for raw in raw_products:
        # Schema failures at load are merchant bugs: skip loudly, don't crash.
        try:
            clean, report = firewall.sanitize_listing(raw, key)
        except firewall.SchemaError as exc:
            pid = raw.get("product_id", "?")
            print("catalog: dropping invalid listing %s: %s" % (pid, exc))
            continue
        products[clean["product_id"]] = clean
        reports[clean["product_id"]] = report
    return Catalog(merchant, products, reports, key)
