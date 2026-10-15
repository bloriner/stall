#!/usr/bin/env python3
"""Stall merchant onboarding CLI (v1.0).

A v1.0 Stall store holds ONE merchant catalog (multi-merchant is future
work). Onboarding:

  1. Create a merchant (generates the signing key):
       python3 -m stall.onboard create-merchant --name "Acme Widgets"

     -> merchant_id like "acme-widgets-3f9a2c", key saved to
        merchants/<merchant_id>/merchant.key (chmod 600), record in
        merchants/<merchant_id>/merchant.json. The key is printed ONCE.

  2. Sign a catalog and load it into the store:
       python3 -m stall.onboard sign-catalog --merchant-id <id> \\
           --products products.json [--db /path/to/stall.db]

     -> signs every listing, writes merchants/<id>/products.signed.json,
        and loads the catalog into the store (replaces the current one).

  3. Rotate a compromised key:
       python3 -m stall.onboard rotate-key --merchant-id <id>

Key management (the honest v1 story): the merchant holds their own key.
Stall prints it once and never sees it again; the key file lives on the
merchant's machine with owner-only permissions. If the key leaks, rotate
it and re-run sign-catalog — listings signed with the old key will fail
verification and show as untrusted. Hosted key custody (HSM / vault) is
future work for the hosted Stall service.

products.json format: a JSON array of listings WITHOUT signatures:
  [{"product_id": "w1", "name": "Widget", "price_cents": 999,
    "currency": "USD", "category": "tools",
    "attributes": {"color": "red"}, "description": "..."}]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
MERCHANTS_DIR = os.path.join(REPO_ROOT, "merchants")

sys.path.insert(0, REPO_ROOT)

from stall import firewall  # noqa: E402
from stall import store as store_mod  # noqa: E402


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "merchant"


def _merchant_dir(merchant_id: str) -> str:
    return os.path.join(MERCHANTS_DIR, merchant_id)


def _key_path(merchant_id: str) -> str:
    return os.path.join(_merchant_dir(merchant_id), "merchant.key")


def _record_path(merchant_id: str) -> str:
    return os.path.join(_merchant_dir(merchant_id), "merchant.json")


def _load_key(merchant_id: str) -> bytes:
    path = _key_path(merchant_id)
    if not os.path.exists(path):
        raise SystemExit(
            "no key file for merchant %r (expected %s). "
            "Was the merchant created with create-merchant?" % (merchant_id, path))
    with open(path, "rb") as f:
        key = f.read().strip()
    if not key:
        raise SystemExit("key file %s is empty — rotate the key" % path)
    return key


def cmd_create_merchant(args) -> int:
    slug = _slugify(args.name)
    merchant_id = "%s-%s" % (slug, secrets.token_hex(3))
    key = secrets.token_hex(32)  # 32 bytes, hex-encoded
    mdir = _merchant_dir(merchant_id)
    os.makedirs(mdir, exist_ok=False)
    record = {
        "merchant_id": merchant_id,
        "name": args.name,
        "since": __import__("datetime").date.today().isoformat(),
        "description": args.description or "",
    }
    with open(_record_path(merchant_id), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    # Owner-only permissions: the key file must not be world-readable.
    fd = os.open(_key_path(merchant_id), os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    print("merchant created: %s" % merchant_id)
    print("record: %s" % _record_path(merchant_id))
    print()
    print("=" * 64)
    print("SIGNING KEY (shown ONCE — store it somewhere safe, e.g. a")
    print("password manager). Stall cannot recover it for you.")
    print("=" * 64)
    print(key)
    print("=" * 64)
    print("Also saved (owner-only) to: %s" % _key_path(merchant_id))
    print()
    print("Next: python3 -m stall.onboard sign-catalog "
          "--merchant-id %s --products products.json" % merchant_id)
    return 0


def cmd_sign_catalog(args) -> int:
    merchant_id = args.merchant_id
    record_path = _record_path(merchant_id)
    if not os.path.exists(record_path):
        raise SystemExit("unknown merchant %r — run create-merchant first"
                         % merchant_id)
    with open(record_path, encoding="utf-8") as f:
        merchant = json.load(f)
    key = _load_key(merchant_id)
    with open(args.products, encoding="utf-8") as f:
        raw_products = json.load(f)
    if not isinstance(raw_products, list) or not raw_products:
        raise SystemExit("--products must be a non-empty JSON array")

    signed = []
    for raw in raw_products:
        product = {k: v for k, v in raw.items() if k != "signature"}
        # Validate BEFORE signing so a broken listing fails here, loudly,
        # instead of shipping an unsignable catalog.
        firewall.validate_schema(product)
        product["signature"] = firewall.sign_listing(product, key)
        signed.append(product)

    out_path = os.path.join(_merchant_dir(merchant_id),
                            "products.signed.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2)
        f.write("\n")
    print("signed %d listings -> %s" % (len(signed), out_path))

    # Load into the store (replaces the current catalog — v1 holds one
    # merchant at a time).
    db_path = args.db or os.environ.get("STALL_DB")
    store = (store_mod.SQLiteStore(db_path) if db_path
             else store_mod.SQLiteStore(store_mod._default_db_path()))
    try:
        stats = store.seed_catalog(merchant, signed, key)
    finally:
        store.close()
    print("loaded into store (%s): %s"
          % (db_path or store_mod._default_db_path(), stats))
    if stats["signatures_invalid"]:
        print("WARNING: %d listings have invalid signatures"
              % stats["signatures_invalid"])
    if stats["listings_sanitized"]:
        print("note: %d listings were sanitized by the firewall "
              "(see their firewall reports)" % stats["listings_sanitized"])
    return 0


def cmd_rotate_key(args) -> int:
    merchant_id = args.merchant_id
    if not os.path.exists(_record_path(merchant_id)):
        raise SystemExit("unknown merchant %r" % merchant_id)
    old_path = _key_path(merchant_id)
    if os.path.exists(old_path):
        os.replace(old_path,
                   old_path + ".revoked-%s" % secrets.token_hex(4))
    key = secrets.token_hex(32)
    fd = os.open(old_path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    print("key rotated for %s (old key archived as .revoked-*)" % merchant_id)
    print()
    print("=" * 64)
    print("NEW SIGNING KEY (shown ONCE):")
    print("=" * 64)
    print(key)
    print("=" * 64)
    print("Re-run sign-catalog: listings signed with the old key will now")
    print("verify as UNTRUSTED until re-signed.")
    return 0


def cmd_show(args) -> int:
    merchant_id = args.merchant_id
    record_path = _record_path(merchant_id)
    if not os.path.exists(record_path):
        raise SystemExit("unknown merchant %r" % merchant_id)
    with open(record_path, encoding="utf-8") as f:
        print(json.dumps(json.load(f), indent=2))
    # The key itself is never printed by show.
    print("key file: %s (use rotate-key to replace)"
          % _key_path(merchant_id))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="stall.onboard", description="Stall merchant onboarding")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create-merchant", help="create a merchant + key")
    c.add_argument("--name", required=True, help="merchant display name")
    c.add_argument("--description", default="",
                   help="short merchant description")
    c.set_defaults(fn=cmd_create_merchant)

    s = sub.add_parser("sign-catalog",
                       help="sign listings and load them into the store")
    s.add_argument("--merchant-id", required=True)
    s.add_argument("--products", required=True,
                   help="JSON array of listings (no signatures)")
    s.add_argument("--db", default=None,
                   help="sqlite path (default: repo stall.db / STALL_DB)")
    s.set_defaults(fn=cmd_sign_catalog)

    r = sub.add_parser("rotate-key", help="replace a compromised key")
    r.add_argument("--merchant-id", required=True)
    r.set_defaults(fn=cmd_rotate_key)

    w = sub.add_parser("show", help="show the merchant record (not the key)")
    w.add_argument("--merchant-id", required=True)
    w.set_defaults(fn=cmd_show)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
