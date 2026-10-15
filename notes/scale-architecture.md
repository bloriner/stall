# Stall scale architecture (v0.2)

How Stall goes from a demo to many products and millions of customers.
This is a design + foundation build: the seams are in place, the
exotic parts are explicitly future work.

## The shape of the system

```
 agents ──► MCP servers (stateless, N behind a load balancer)
                    │
                    ▼
              Store interface
              ├── MemoryStore   (tests, single-process demos)
              ├── SQLiteStore   (v0.2: durable single node, FTS5 search)
              └── PostgresStore (future: multi-node)
                    │
                    ▼
              firewall.sanitize_listings  (per-listing pure function,
                                           embarrassingly parallel)
```

Three hard rules make scale possible:

1. **MCP servers hold no session state.** Carts, the spend ledger, and
   receipts all live in the store. A server process is just a translator
   between JSON-RPC and store calls, so you run as many as you need.
   (v0.2 keeps the stdio transport from the MCP spec; a production
   deployment would put these behind an SSE/HTTP bridge — the store
   seam is what matters, the transport is swappable.)
2. **The firewall is a pure function of one listing.** `sanitize_listing`
   takes `(raw_dict, merchant_key)` and returns `(clean, report)` — no
   shared state, no I/O. At catalog scale it runs in a worker pool
   (`multiprocessing.Pool.map` over `sanitize_listings` chunks), and only
   sanitized listings ever touch the database.
3. **Money movement is a single atomic transaction.** `commit_purchase`
   checks caps and records spend in ONE step. There is no window between
   "are you allowed?" and "you spent it", so concurrent checkouts cannot
   overspend no matter how many servers are running.

## Storage backends

| concern | MemoryStore | SQLiteStore (v0.2) | PostgresStore (future) |
|---|---|---|---|
| products | dict | table + FTS5 index | table + tsvector/GIN |
| search | linear scan + rank | FTS5 candidates + same ranker | same |
| carts | dict | tables | tables |
| spend ledger | dicts + RLock | `BEGIN IMMEDIATE` txn | `SELECT … FOR UPDATE` on the `(agent, day)` ledger row |
| atomicity | process-local | single node | multi-node |

Ranking is identical everywhere: FTS5 (or Postgres) only *narrows
candidates*; the deterministic `catalog.rank_products` scorer orders them,
so results don't change when you swap backends. Verified by
`TestBackendParity`.

Sharding: catalogs shard by `merchant_id` (each merchant's products live
together; the firewall already runs per merchant). The spend ledger shards
by `(agent_id, day)` — the natural contention domain, since caps are
per-agent-per-day. Postgres row-level locking on the ledger row gives the
same atomicity as SQLite's `BEGIN IMMEDIATE` without a global write lock.

Caching (future, noted not built): product summaries are immutable once
firewalled (listings are content-addressed by `product_id` + signature),
so they cache perfectly in Redis/Memcached. The spend ledger must NOT be
cached — it's the one read-your-writes path.

## Capacity sketch (single SQLite node, honest numbers)

Measured on this dev VM (v0.2 test run):

- **Catalog ingest:** ~10k listings through the firewall + FTS5 index in
  low single-digit seconds (~2–4k listings/sec single-threaded; the
  firewall is CPU-bound regex work, so it scales ~linearly with cores in
  a worker pool).
- **Product search:** FTS5 candidate retrieval + Python re-rank. Measured on
  10k products: ~150–250ms worst case (every listing matches, all 10k
  re-ranked), ~15–180ms for selective queries. FTS5 handles millions of
  rows; the re-rank only touches candidates, so typical agent queries
  (2–4 distinctive tokens) stay fast. The 10k sanity test asserts < 2s.
- **Checkout:** one `BEGIN IMMEDIATE` transaction doing two SUM reads +
  two INSERTs. SQLite does ~300–1,000 such write transactions/sec on
  ordinary SSD storage (fsync-bound). That's the per-node ceiling for
  purchases — reads (search, cart, product) scale independently and far
  higher.
- **MCP servers:** stateless, so add processes until the DB write rate is
  the limit. Each stdio server handles one agent session; behind an
  SSE bridge you'd run hundreds per box.

Where the bottlenecks really are, in order:

1. **Spend-ledger write serialization.** Every purchase in the world
   funnels through one logical counter per (agent, day). At millions of
   customers this is fine — contention is per-agent, not global — but a
   flash sale (one merchant, thousands of agents) still serializes on the
   merchant's row in Postgres. Mitigation: ledger per (agent, merchant,
   day), which is already the schema shape.
2. **FTS index size.** Fine to ~10M listings per node; beyond that, shard
   the catalog by merchant_id across nodes.
3. **Receipt chain.** The HMAC chain is per-server-process in v0.2 and can
   fork under concurrency (two checkouts reading the same prev_hash).
   It's tamper-evidence, not a consensus protocol — acceptable for the
   demo, but a production ledger would sequence receipts in the DB.

## What v0.2 implements vs. what's future

Implemented:
- `stall/store.py`: Store interface + MemoryStore + SQLiteStore
- FTS5 product search with identical ranking across backends
- Atomic spend ledger (`commit_purchase`: check + record in one txn)
- Stateless MCP server wired to the store (`STALL_DB` / `STALL_STORE`)
- Firewall as a parallelizable per-listing pure function
  (`sanitize_listings` batch entry point)
- Race tests proving no overspend under 10-thread concurrency

Future (documented, not built):
- PostgresStore (`SELECT … FOR UPDATE` variant of the same interface)
- Redis-style cache for product summaries
- SSE/HTTP transport bridge for the MCP servers
- Catalog sharding by merchant_id across nodes
- x402 settlement rail (the receipt is still a purchase *intent*)
- Sequenced (non-forking) receipt ledger
