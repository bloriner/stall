#!/usr/bin/env python3
"""Stall storage abstraction.

The Store interface separates the MCP server from persistence. Every
session-scoped object (carts, spend ledger, receipts) lives in the store,
which makes MCP servers stateless: N servers can sit behind a load balancer
with no shared memory. Two backends:

- MemoryStore: the v0.1 in-memory behavior (Catalog + dicts + lock). For
  tests and single-process demos.
- SQLiteStore: durable single-node backend. Product search runs on an FTS5
  index; the spend ledger is updated inside an atomic transaction
  (check caps + record spend in ONE step — no race between check and charge).

Seams for scale (see notes/scale-architecture.md):
- Catalog shards by merchant_id; the firewall runs per-listing and is
  embarrassingly parallel (see firewall.sanitize_listings).
- The Postgres path keeps the same interface; the only change is the
  atomicity primitive (SELECT ... FOR UPDATE on the ledger row instead of
  BEGIN IMMEDIATE).
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import uuid
from abc import ABC, abstractmethod
from datetime import date

from . import catalog as catalog_mod
from . import firewall
from .catalog import rank_products
from .guardrails import GuardrailConfig, evaluate_caps

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
DEMO_DIR = os.path.join(REPO_ROOT, "demo")


class Store(ABC):
    """Persistence interface. All methods are safe to call from threads."""

    # -- catalog ------------------------------------------------------
    @abstractmethod
    def seed_catalog(self, merchant: dict, raw_products: list[dict],
                     merchant_key: bytes) -> dict:
        """Replace the catalog. Returns firewall stats dict."""

    @abstractmethod
    def merchant_id(self) -> str | None:
        """None when no catalog has been seeded yet."""

    @abstractmethod
    def merchant(self) -> dict | None: ...

    @abstractmethod
    def get_product(self, product_id: str) -> dict | None:
        """Sanitized product, or None."""

    @abstractmethod
    def firewall_report(self, product_id: str) -> dict | None: ...

    @abstractmethod
    def search_products(self, query: str, category: str | None = None,
                        max_results: int = 10) -> list[dict]:
        """Sanitized product summaries, ranked like v0.1."""

    @abstractmethod
    def firewall_stats(self) -> dict: ...

    # -- carts --------------------------------------------------------
    @abstractmethod
    def create_cart(self) -> str: ...

    @abstractmethod
    def get_cart(self, cart_id: str) -> dict | None:
        """{product_id: qty}, or None for unknown cart."""

    @abstractmethod
    def add_to_cart(self, cart_id: str, product_id: str, qty: int) -> None:
        """Raises KeyError on unknown cart or product."""

    @abstractmethod
    def delete_cart(self, cart_id: str) -> None: ...

    # -- spend ledger (atomic) ----------------------------------------
    @abstractmethod
    def commit_purchase(self, *, total_cents: int, merchant_id: str,
                        config: GuardrailConfig, approval: bool,
                        receipt_builder) -> tuple[bool, str | None, dict | None]:
        """Atomically evaluate caps and, if allowed, build the receipt,
        record the spend, and store the receipt. receipt_builder(prev_hash)
        -> receipt dict is called INSIDE the atomic section with the fresh
        chain head, so concurrent checkouts can never fork the receipt
        chain. Returns (allowed, reason, receipt)."""

    # -- receipts ------------------------------------------------------
    @abstractmethod
    def last_receipt_hash(self) -> str: ...


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _summary(product: dict, signature_valid: bool) -> dict:
    return {
        "product_id": product["product_id"],
        "name": product["name"],
        "price_cents": product["price_cents"],
        "currency": product["currency"],
        "category": product["category"],
        "signature_valid": signature_valid,
    }


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------

class MemoryStore(Store):
    """v0.1 behavior: everything in memory, guarded by one lock."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._merchant: dict | None = None
        self._products: dict[str, dict] = {}
        self._reports: dict[str, dict] = {}
        self._carts: dict[str, dict[str, int]] = {}
        self._merchant_spend: dict[str, int] = {}
        self._daily_spend: dict[str, int] = {}
        self._receipts: list[dict] = []
        self._last_hash = "0" * 64

    # -- catalog --
    def seed_catalog(self, merchant, raw_products, merchant_key):
        clean = firewall.sanitize_listings(raw_products, merchant_key)
        with self._lock:
            self._merchant = dict(merchant)
            self._products = {p["product_id"]: p for p, _ in clean}
            self._reports = {p["product_id"]: r for p, r in clean}
            return self.firewall_stats()

    def merchant_id(self):
        return self._merchant["merchant_id"] if self._merchant else None

    def merchant(self):
        return dict(self._merchant) if self._merchant else None

    def get_product(self, product_id):
        return self._products.get(product_id)

    def firewall_report(self, product_id):
        return self._reports.get(product_id)

    def search_products(self, query, category=None, max_results=10):
        products = list(self._products.values())
        if category:
            products = [p for p in products
                        if p["category"].lower() == category.lower()]
        ranked = rank_products(products, query, max_results)
        return [_summary(p, self._reports[p["product_id"]]["signature_valid"])
                for p in ranked]

    def firewall_stats(self):
        total = len(self._reports)
        valid = sum(1 for r in self._reports.values() if r["signature_valid"])
        sanitized = sum(1 for r in self._reports.values() if r["sanitized"])
        return {
            "products_total": total,
            "signatures_valid": valid,
            "signatures_invalid": total - valid,
            "listings_sanitized": sanitized,
        }

    # -- carts --
    def create_cart(self):
        cart_id = uuid.uuid4().hex
        with self._lock:
            self._carts[cart_id] = {}
        return cart_id

    def get_cart(self, cart_id):
        with self._lock:
            cart = self._carts.get(cart_id)
            return dict(cart) if cart is not None else None

    def add_to_cart(self, cart_id, product_id, qty):
        with self._lock:
            if cart_id not in self._carts:
                raise KeyError("unknown cart_id")
            if product_id not in self._products:
                raise KeyError("unknown product_id: %r" % (product_id,))
            cart = self._carts[cart_id]
            cart[product_id] = cart.get(product_id, 0) + qty

    def delete_cart(self, cart_id):
        with self._lock:
            self._carts.pop(cart_id, None)

    # -- ledger --
    def commit_purchase(self, *, total_cents, merchant_id, config,
                        approval, receipt_builder):
        from .guardrails import receipt_hash
        today = date.today().isoformat()
        with self._lock:
            m_spend = self._merchant_spend.get(merchant_id, 0)
            d_spend = self._daily_spend.get(today, 0)
            allowed, reason = evaluate_caps(
                total_cents, merchant_id, m_spend, d_spend, config,
                approval=approval)
            if not allowed:
                return False, reason, None
            # The receipt is built inside the lock with the fresh chain
            # head: concurrent checkouts serialize here, so the chain can
            # never fork.
            receipt = receipt_builder(self._last_hash)
            self._merchant_spend[merchant_id] = m_spend + total_cents
            self._daily_spend[today] = d_spend + total_cents
            self._receipts.append(receipt)
            self._last_hash = receipt_hash(receipt)
            return True, None, receipt

    def last_receipt_hash(self):
        with self._lock:
            return self._last_hash


# ---------------------------------------------------------------------------
# SQLiteStore
# ---------------------------------------------------------------------------

_FTS_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _fts_tokens(query: str) -> list[str]:
    # Split (don't delete) on non-alphanumerics so hyphenated queries like
    # "SKU-4242" become ["sku", "4242"] — matching FTS5's own tokenization.
    # The deterministic re-ranker then applies v0.1's exact substring
    # semantics, so behavior stays identical to the memory backend.
    return [t for t in _FTS_TOKEN_RE.sub(" ", query.lower()).split() if t]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
    product_id TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    category TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    description TEXT NOT NULL,
    signature_valid INTEGER NOT NULL,
    report_json TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS products_fts USING fts5(
    product_id UNINDEXED,
    name,
    category,
    description,
    attributes_text
);
CREATE TABLE IF NOT EXISTS carts (
    cart_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cart_items (
    cart_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    qty INTEGER NOT NULL,
    PRIMARY KEY (cart_id, product_id)
);
CREATE TABLE IF NOT EXISTS spend_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id TEXT NOT NULL,
    day TEXT NOT NULL,
    cents INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_spend_merchant_day
    ON spend_ledger (merchant_id, day);
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    receipt_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hmac TEXT NOT NULL
);
"""


def _auto_reconnect(fn):
    """Retry a store write once after recreating a vanished DB file.

    If the sqlite file is deleted mid-run, writes fail with
    "attempt to write a readonly database". Instead of crashing the
    server, recreate the file and retry the operation once. Reads keep
    working off the stale file handle until the next write triggers the
    reconnect.
    """
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except sqlite3.OperationalError as exc:
            if "readonly" not in str(exc).lower():
                raise
            self._reconnect()
            return fn(self, *args, **kwargs)
    return wrapper


class SQLiteStore(Store):
    """Durable single-node backend.

    - Product search: FTS5 index narrows candidates, then the deterministic
      v0.1 ranker orders them (identical results to MemoryStore).
    - Spend ledger: BEGIN IMMEDIATE transaction — the writer lock is held
      from check through record, so concurrent checkouts cannot overspend.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(path, check_same_thread=False,
                                         isolation_level=None)
        except sqlite3.OperationalError as exc:
            raise RuntimeError("cannot open sqlite db %r: %s" % (path, exc))
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.executescript(_SCHEMA)
        except sqlite3.OperationalError as exc:
            if "fts5" in str(exc).lower():
                raise RuntimeError("sqlite FTS5 unavailable: %s" % exc)
            raise RuntimeError(
                "sqlite database error on %r: %s" % (path, exc))
        except sqlite3.DatabaseError as exc:
            # e.g. "file is not a database". Never silently delete user
            # data: fail loud with the recovery step.
            raise RuntimeError(
                "sqlite database %r is corrupt or not a database: %s "
                "(move it aside to start fresh)" % (path, exc))

    # -- internal --
    def _row_to_product(self, row: sqlite3.Row) -> dict:
        return {
            "product_id": row["product_id"],
            "name": row["name"],
            "price_cents": row["price_cents"],
            "currency": row["currency"],
            "category": row["category"],
            "attributes": json.loads(row["attributes_json"]),
            "description": row["description"],
        }

    # -- catalog --
    @_auto_reconnect
    def seed_catalog(self, merchant, raw_products, merchant_key):
        # Firewall first (pure per-listing function — parallelizable), then
        # one transaction for the whole catalog swap.
        clean = firewall.sanitize_listings(raw_products, merchant_key)
        mid = merchant["merchant_id"]
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute("DELETE FROM products")
                cur.execute("DELETE FROM products_fts")
                for product, report in clean:
                    attrs = product["attributes"]
                    cur.execute(
                        "INSERT INTO products (product_id, merchant_id, name,"
                        " price_cents, currency, category, attributes_json,"
                        " description, signature_valid, report_json)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (product["product_id"], mid, product["name"],
                         product["price_cents"], product["currency"],
                         product["category"], json.dumps(attrs),
                         product["description"],
                         1 if report["signature_valid"] else 0,
                         json.dumps(report)),
                    )
                    cur.execute(
                        "INSERT INTO products_fts (product_id, name, category,"
                        " description, attributes_text)"
                        " VALUES (?,?,?,?,?)",
                        (product["product_id"], product["name"],
                         product["category"], product["description"],
                         " ".join("%s %s" % (k, v)
                                   for k, v in attrs.items())),
                    )
                cur.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    ("merchant", json.dumps(merchant)),
                )
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
            return self.firewall_stats()

    def merchant_id(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='merchant'").fetchone()
        if row is None:
            return None
        return json.loads(row["value"])["merchant_id"]

    def merchant(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='merchant'").fetchone()
        return json.loads(row["value"]) if row else None

    def get_product(self, product_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM products WHERE product_id=?",
                (product_id,)).fetchone()
        return self._row_to_product(row) if row else None

    def firewall_report(self, product_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT report_json FROM products WHERE product_id=?",
                (product_id,)).fetchone()
        return json.loads(row["report_json"]) if row else None

    def search_products(self, query, category=None, max_results=10):
        tokens = _fts_tokens(query)
        with self._lock:
            if tokens:
                match = " OR ".join('"%s"' % t for t in tokens)
                rows = self._conn.execute(
                    "SELECT p.* FROM products_fts f"
                    " JOIN products p ON p.product_id = f.product_id"
                    " WHERE products_fts MATCH ?",
                    (match,)).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM products").fetchall()
        products = [self._row_to_product(r) for r in rows]
        if category:
            products = [p for p in products
                        if p["category"].lower() == category.lower()]
        ranked = rank_products(products, query, max_results)
        # signature flags ride along via a second cheap lookup
        with self._lock:
            flags = {
                r["product_id"]: bool(r["signature_valid"])
                for r in self._conn.execute(
                    "SELECT product_id, signature_valid FROM products")
            }
        return [_summary(p, flags[p["product_id"]]) for p in ranked]

    def firewall_stats(self):
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM products").fetchone()[0]
            valid = self._conn.execute(
                "SELECT COUNT(*) FROM products WHERE signature_valid=1"
            ).fetchone()[0]
            reports = [json.loads(r[0]) for r in self._conn.execute(
                "SELECT report_json FROM products")]
        sanitized = sum(1 for r in reports if r["sanitized"])
        return {
            "products_total": total,
            "signatures_valid": valid,
            "signatures_invalid": total - valid,
            "listings_sanitized": sanitized,
        }

    # -- carts --
    @_auto_reconnect
    def create_cart(self):
        from datetime import datetime, timezone
        cart_id = uuid.uuid4().hex
        with self._lock:
            self._conn.execute(
                "INSERT INTO carts (cart_id, created_at) VALUES (?, ?)",
                (cart_id,
                 datetime.now(timezone.utc).isoformat(timespec="seconds")))
        return cart_id

    def get_cart(self, cart_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM carts WHERE cart_id=?", (cart_id,)).fetchone()
            if row is None:
                return None
            items = self._conn.execute(
                "SELECT product_id, qty FROM cart_items WHERE cart_id=?",
                (cart_id,)).fetchall()
        return {r["product_id"]: r["qty"] for r in items}

    @_auto_reconnect
    def add_to_cart(self, cart_id, product_id, qty):
        with self._lock:
            if self._conn.execute(
                    "SELECT 1 FROM carts WHERE cart_id=?",
                    (cart_id,)).fetchone() is None:
                raise KeyError("unknown cart_id")
            if self._conn.execute(
                    "SELECT 1 FROM products WHERE product_id=?",
                    (product_id,)).fetchone() is None:
                raise KeyError("unknown product_id: %r" % (product_id,))
            cur = self._conn.execute(
                "UPDATE cart_items SET qty = qty + ?"
                " WHERE cart_id=? AND product_id=?",
                (qty, cart_id, product_id))
            if cur.rowcount == 0:
                self._conn.execute(
                    "INSERT INTO cart_items (cart_id, product_id, qty)"
                    " VALUES (?,?,?)", (cart_id, product_id, qty))

    @_auto_reconnect
    def delete_cart(self, cart_id):
        with self._lock:
            self._conn.execute("DELETE FROM cart_items WHERE cart_id=?",
                               (cart_id,))
            self._conn.execute("DELETE FROM carts WHERE cart_id=?", (cart_id,))

    # -- ledger (the atomic part) --
    @_auto_reconnect
    def commit_purchase(self, *, total_cents, merchant_id, config,
                        approval, receipt_builder):
        from datetime import datetime, timezone
        today = date.today().isoformat()
        with self._lock:
            cur = self._conn.cursor()
            # IMMEDIATE takes the write lock up front: no other writer can
            # slip a spend between our check and our record, and the
            # receipt is built here with the fresh chain head, so the
            # chain can never fork under concurrency.
            cur.execute("BEGIN IMMEDIATE")
            try:
                m_spend = cur.execute(
                    "SELECT COALESCE(SUM(cents),0) FROM spend_ledger"
                    " WHERE merchant_id=?", (merchant_id,)).fetchone()[0]
                d_spend = cur.execute(
                    "SELECT COALESCE(SUM(cents),0) FROM spend_ledger"
                    " WHERE day=?", (today,)).fetchone()[0]
                allowed, reason = evaluate_caps(
                    total_cents, merchant_id, m_spend, d_spend, config,
                    approval=approval)
                if not allowed:
                    cur.execute("ROLLBACK")
                    return False, reason, None
                row = cur.execute(
                    "SELECT hmac FROM receipts"
                    " ORDER BY rowid DESC LIMIT 1").fetchone()
                prev_hash = (hashlib.sha256(
                    row[0].encode("utf-8")).hexdigest() if row else "0" * 64)
                receipt = receipt_builder(prev_hash)
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                cur.execute(
                    "INSERT INTO spend_ledger (merchant_id, day, cents,"
                    " created_at) VALUES (?,?,?,?)",
                    (merchant_id, today, total_cents, now))
                cur.execute(
                    "INSERT INTO receipts (receipt_id, receipt_json,"
                    " prev_hash, hmac) VALUES (?,?,?,?)",
                    (receipt["receipt_id"], json.dumps(receipt),
                     receipt.get("prev_hash", ""), receipt.get("hmac", "")))
                cur.execute("COMMIT")
                return True, None, receipt
            except Exception:
                try:
                    cur.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def last_receipt_hash(self):
        from .guardrails import receipt_hash
        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_json FROM receipts"
                " ORDER BY rowid DESC LIMIT 1").fetchone()
        if row is None:
            return "0" * 64
        return receipt_hash(json.loads(row["receipt_json"]))

    def close(self):
        with self._lock:
            self._conn.close()

    # -- resilience --
    def _reconnect(self) -> None:
        """Recreate the database file and schema after it vanished
        mid-run (deleted file, tmp cleaner, disk hiccup). The store comes
        back EMPTY — catalog data must be reloaded (see stall.onboard).
        Never silently recovers data; it only keeps the server serving."""
        print("stall: database file %r vanished mid-run; recreated empty "
              "schema (reload the catalog)" % self._path, file=sys.stderr)
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = sqlite3.connect(self._path, check_same_thread=False,
                                         isolation_level=None)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# factory
# ---------------------------------------------------------------------------

def _default_db_path() -> str:
    return os.path.join(REPO_ROOT, "stall.db")


def _read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def seed_demo(store: Store) -> dict:
    """Seed the store with the demo merchant + firewall-sanitized catalog."""
    merchant = _read_json(os.path.join(DEMO_DIR, "merchant.json"))
    raw_products = _read_json(os.path.join(DEMO_DIR, "products.json"))
    key = merchant["hmac_key"].encode("utf-8")
    return store.seed_catalog(merchant, raw_products, key)


def make_store() -> Store:
    """Build a store from the environment.

    STALL_STORE=memory  -> MemoryStore (tests, single-process demos)
    STALL_DB=<path>     -> SQLiteStore at <path>
    (default)           -> SQLiteStore at <repo>/stall.db
    Seeds the demo catalog when the store is empty.
    """
    backend = os.environ.get("STALL_STORE", "").strip().lower()
    if backend == "memory":
        store: Store = MemoryStore()
    else:
        store = SQLiteStore(os.environ.get("STALL_DB") or _default_db_path())
    if store.merchant_id() is None:
        seed_demo(store)
    return store
