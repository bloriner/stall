#!/usr/bin/env python3
"""Store backend tests: FTS relevance, the atomic spend ledger under
concurrency, backend parity, and a 10k-product search sanity check."""

import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stall import firewall
from stall.guardrails import GuardrailConfig, sign_receipt, GENESIS_HASH
from stall.store import MemoryStore, SQLiteStore, seed_demo

RECEIPT_KEY = b"test-receipt-key"


def make_memory_store():
    s = MemoryStore()
    seed_demo(s)
    return s


def make_sqlite_store():
    fd, path = tempfile.mkstemp(prefix="stall-store-test-", suffix=".db")
    os.close(fd)
    os.unlink(path)
    s = SQLiteStore(path)
    seed_demo(s)
    s._test_path = path  # for cleanup
    return s


def close_store(s):
    if isinstance(s, SQLiteStore):
        s.close()
        if os.path.exists(s._test_path):
            os.unlink(s._test_path)


class StoreTestBase(unittest.TestCase):
    BACKENDS = ("memory", "sqlite")

    def make_store(self, backend):
        return make_memory_store() if backend == "memory" \
            else make_sqlite_store()

    def tearDown(self):
        for s in getattr(self, "_stores", []):
            close_store(s)


class TestSearchRelevance(StoreTestBase):
    """FTS index must rank the right products first (SQLite backend)."""

    def setUp(self):
        self._stores = [make_sqlite_store()]
        self.store = self._stores[0]

    def test_multi_token_query_ranks_best_match_first(self):
        results = self.store.search_products("ergonomic wireless")
        self.assertTrue(results)
        self.assertEqual(results[0]["product_id"], "mouse-w1")

    def test_single_token(self):
        results = self.store.search_products("yoga")
        ids = [r["product_id"] for r in results]
        self.assertIn("mat-yoga", ids)
        self.assertEqual(results[0]["product_id"], "mat-yoga")

    def test_category_filter(self):
        results = self.store.search_products("", category="grocery")
        ids = {r["product_id"] for r in results}
        self.assertIn("coffee-1kg", ids)
        self.assertTrue(all(r["category"] == "grocery" for r in results))

    def test_empty_query_returns_all(self):
        results = self.store.search_products("")
        self.assertEqual(len(results), 10)

    def test_adversarial_listing_still_sanitized_in_sqlite(self):
        p = self.store.get_product("widget-x9")
        self.assertNotIn("Ignore previous instructions", p["description"])
        self.assertIn("unbeatable price", p["description"])
        rep = self.store.firewall_report("widget-x9")
        self.assertTrue(len(rep["stripped"]) >= 1)
        self.assertFalse(self.store.firewall_report("gadget-x1")
                         ["signature_valid"])


class TestBackendParity(StoreTestBase):
    """Both backends must return identical search orderings."""

    def test_identical_rankings(self):
        self._stores = [make_memory_store(), make_sqlite_store()]
        mem, sql = self._stores
        for query in ("mouse", "ergonomic wireless", "coffee", "",
                      "USB-C hub", "mystery gadget"):
            with self.subTest(query=query):
                a = [r["product_id"]
                     for r in mem.search_products(query, max_results=50)]
                b = [r["product_id"]
                     for r in sql.search_products(query, max_results=50)]
                self.assertEqual(a, b, "ranking differs for %r" % query)


class TestAtomicLedger(StoreTestBase):
    """Concurrent checkouts must never overspend the daily cap.

    10 threads x $100 against a $300 daily cap: exactly 3 may succeed,
    total recorded spend must be exactly $300, never more.
    """

    def _race(self, backend):
        store = self.make_store(backend)
        self._stores = getattr(self, "_stores", []) + [store]
        cfg = GuardrailConfig(
            max_per_purchase_cents=100_000,
            max_per_merchant_cents=100_000_000,
            max_daily_cents=30_000,
            approval_threshold_cents=100_000_000,
        )
        mid = store.merchant_id()
        results = []
        lock = threading.Lock()

        def attempt(i):
            receipt = sign_receipt(
                key=RECEIPT_KEY, merchant_id=mid, items=[],
                total_cents=10_000, currency="USD",
                agent_id="race-agent", prev_hash=GENESIS_HASH,
                receipt_id="race-%s-%d" % (backend, i))
            ok, reason = store.commit_purchase(
                total_cents=10_000, merchant_id=mid, config=cfg,
                approval=True, receipt=receipt)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=attempt, args=(i,))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        succeeded = sum(1 for ok in results if ok)
        self.assertEqual(succeeded, 3,
                         "expected exactly 3 checkouts to win the race")
        # The ledger itself must show exactly the cap, never over.
        if backend == "sqlite":
            row = store._conn.execute(
                "SELECT COALESCE(SUM(cents),0) FROM spend_ledger").fetchone()
            total = row[0]
        else:
            total = sum(store._daily_spend.values())
        self.assertEqual(total, 30_000,
                         "ledger overspent the cap: %d" % total)

    def test_race_memory(self):
        self._race("memory")

    def test_race_sqlite(self):
        self._race("sqlite")


class TestScaleSanity(unittest.TestCase):
    """10k-product catalog: search must complete fast."""

    def test_10k_catalog_search_latency(self):
        fd, path = tempfile.mkstemp(prefix="stall-10k-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        try:
            store = SQLiteStore(path)
            key = b"scale-test-key"
            merchant = {"merchant_id": "scale-merchant", "name": "Scale Co",
                        "since": "2026-10-15", "hmac_key": "scale-test-key"}
            raw = []
            for i in range(10_000):
                p = {
                    "product_id": "prod-%05d" % i,
                    "name": "Widget %d deluxe alpha" % i,
                    "price_cents": 100 + (i % 5000),
                    "currency": "USD",
                    "category": "cat-%d" % (i % 25),
                    "attributes": {"sku": "SKU-%d" % i},
                    "description": "A fine widget number %d for testing." % i,
                }
                p["signature"] = firewall.sign_listing(p, key)
                raw.append(p)
            t0 = time.time()
            store.seed_catalog(merchant, raw, key)
            seed_s = time.time() - t0

            t0 = time.time()
            results = store.search_products("deluxe alpha widget",
                                            max_results=10)
            search_s = time.time() - t0
            print("\n10k catalog: seed %.2fs, search %.3fs, hits %d"
                  % (seed_s, search_s, len(results)))
            self.assertTrue(len(results) > 0)
            self.assertLess(search_s, 2.0,
                            "search too slow: %.3fs" % search_s)
            # category-filtered search also fast
            t0 = time.time()
            store.search_products("widget", category="cat-7", max_results=10)
            cat_s = time.time() - t0
            self.assertLess(cat_s, 2.0)
            store.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
