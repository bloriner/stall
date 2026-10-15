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


def score_product(product: dict, tokens: list[str]) -> int:
    """v0.1 ranking score: count of query tokens in the listing text."""
    hay = " ".join([
        product["name"], product["category"], product["description"],
        *[str(v) for v in product["attributes"].values()],
    ]).lower()
    return sum(1 for t in tokens if t in hay)


def rank_products(products: list[dict], query: str,
                  max_results: int) -> list[dict]:
    """Deterministic ranking shared by every Store backend, so results are
    identical whether the catalog lives in memory or in SQLite."""
    tokens = [t for t in query.lower().split() if t]
    scored = [(score_product(p, tokens), p) for p in products]
    scored = [(s, p) for s, p in scored if s or not tokens]
    scored.sort(key=lambda sp: (-sp[0], sp[1]["name"]))
    return [p for _, p in scored[:max_results]]


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
        products = list(self.products.values())
        if category:
            products = [p for p in products
                        if p["category"].lower() == category.lower()]
        return [self.summary(p)
                for p in rank_products(products, query, max_results)]

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
    # sanitize_listings is the parallelizable batch entry point; the
    # per-listing pure function is what a worker pool would map over.
    clean = firewall.sanitize_listings(raw_products, key)
    products = {p["product_id"]: p for p, _ in clean}
    reports = {p["product_id"]: r for p, r in clean}
    return Catalog(merchant, products, reports, key)
