#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MikroWizard template catalog tool (offline; the private key never leaves this machine).

  keygen  --out DIR                        new Ed25519 key pair (private.pem + public.b64)
  export  --db POSTGRES_URL --out SRC      system templates of a database -> SRC/templates/<brand>/<os_type>.json
  build   --src SRC --out catalog.json [--previous OLD_catalog.json] [--version N]
          revisions: a template whose content differs from OLD gets revision+1 and OLD's hash
          in previous_hashes (installs still on the old content update without review)
  sign    --key private.pem catalog.json   -> catalog.json.sig (base64)
  verify  --pub public.b64 catalog.json    checks catalog.json.sig and the catalog format
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys

try:
    import psycopg2
except ImportError:  # only 'export' needs it
    psycopg2 = None
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CONTENT_FIELDS = ("protocol", "connection", "prompt", "privilege_escalation", "commands", "pagination",
                  "error_patterns", "post_login_commands", "pre_logout_commands", "diff_exclusions",
                  "pre_connect", "post_disconnect", "config_mode")
IDENTITY_FIELDS = ("brand", "os_type")
MANAGED_FIELDS = ("display_name",)          # MikroWizard-owned: always applied, not in content_hash
KNOWN_FIELDS = IDENTITY_FIELDS + MANAGED_FIELDS + CONTENT_FIELDS
# First MikroWizard version that understands each field. A template that uses a field (non-null)
# must have min_app_version >= that version, so older servers never apply half a template.
# Adding a device_templates column: add it to CONTENT_FIELDS here AND in py/libs/template_catalog.py,
# with the release that adds the column.
FIELD_MIN_APP_VERSION = {f: "2.1.2" for f in KNOWN_FIELDS}
PRO_PROTOCOLS = ("rdp", "vnc")


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def field_hash(value):
    return hashlib.sha256(canon(value).encode("utf-8")).hexdigest()


def add_field_hashes(entry, content):
    """Remember every field value of `content` as shipped by MikroWizard (untouched on installs)."""
    pf = entry.setdefault("previous_field_hashes", {})
    for f in CONTENT_FIELDS:
        h = field_hash(content.get(f))
        if h not in pf.setdefault(f, []):
            pf[f].append(h)
        pf[f].sort()


def content_hash(content):
    return hashlib.sha256(canon({f: content.get(f) for f in CONTENT_FIELDS}).encode("utf-8")).hexdigest()


def tracked_hash(content):
    """Everything an install receives (content + display_name): a change here bumps the revision."""
    return hashlib.sha256(canon({f: content.get(f) for f in MANAGED_FIELDS + CONTENT_FIELDS}).encode("utf-8")).hexdigest()


def version_tuple(v):
    return tuple(int("".join(ch for ch in p if ch.isdigit()) or 0) for p in str(v or "0").split("."))


def regexes(content):
    """Every regular expression the MikroWizard device connector compiles from a template."""
    prompt = content.get("prompt") if isinstance(content.get("prompt"), dict) else {}
    esc = content.get("privilege_escalation") if isinstance(content.get("privilege_escalation"), dict) else {}
    pag = content.get("pagination") if isinstance(content.get("pagination"), dict) else {}
    out = [("prompt pattern", p) for p in (prompt.get("patterns") or [])]
    out += [("prompt.login_pattern", prompt.get("login_pattern")), ("prompt.password_pattern", prompt.get("password_pattern")),
            ("privilege_escalation.prompt", esc.get("prompt")),
            ("privilege_escalation.password_prompt", esc.get("password_prompt")),
            ("privilege_escalation.success_pattern", esc.get("success_pattern")), ("pagination.pattern", pag.get("pattern"))]
    ep = content.get("error_patterns")
    out += [("error pattern", p) for p in ((ep.get("patterns") or []) if isinstance(ep, dict) else (ep if isinstance(ep, list) else []))]
    de = content.get("diff_exclusions")
    for section, rules in (de.items() if isinstance(de, dict) else []):
        for r in (rules if isinstance(rules, list) else []):
            out.append(("diff_exclusions." + section, r.get("pattern") if isinstance(r, dict) else r))
    return [(w, p) for w, p in out if isinstance(p, str) and p]


def keygen(a):
    os.makedirs(a.out, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = os.path.join(a.out, "private.pem")
    with open(path, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    with open(os.path.join(a.out, "public.b64"), "w") as f:
        f.write(pub + "\n")
    print("public key:", pub)


def export(a):
    if psycopg2 is None:
        sys.exit("export needs psycopg2 (pip install psycopg2-binary)")
    conn = psycopg2.connect(a.db)
    cur = conn.cursor()
    cur.execute("SELECT brand, display_name FROM device_brands WHERE is_system = TRUE ORDER BY brand")
    brands = [{"brand": b, "display_name": d} for b, d in cur.fetchall()]
    cols = ["brand", "os_type", "display_name"] + list(CONTENT_FIELDS)
    cur.execute("SELECT {} FROM device_templates WHERE is_system = TRUE ORDER BY brand, os_type".format(", ".join(cols)))
    n = 0
    for row in cur.fetchall():
        c = dict(zip(cols, row))
        d = os.path.join(a.out, "templates", c["brand"])
        os.makedirs(d, exist_ok=True)
        entry = {"key": "{}/{}".format(c["brand"], c["os_type"]), "revision": 1,
                 "edition": "pro" if (c.get("protocol") or "").lower() in PRO_PROTOCOLS else "free",
                 "min_app_version": "2.1.2", "changelog": ["Initial catalog revision (as installed by MikroWizard 2.1.x)"],
                 "previous_hashes": [], "content": c}
        with open(os.path.join(d, "{}.json".format(re.sub(r"[^\w.-]", "_", c["os_type"]))), "w") as f:
            json.dump(entry, f, indent=2, sort_keys=True, ensure_ascii=False)
        n += 1
    with open(os.path.join(a.out, "brands.json"), "w") as f:
        json.dump(brands, f, indent=2, ensure_ascii=False)
    print("exported", n, "templates,", len(brands), "brands")


def _load_src(src):
    entries = []
    for root, _, files in os.walk(os.path.join(src, "templates")):
        for name in sorted(files):
            if name.endswith(".json"):
                with open(os.path.join(root, name)) as f:
                    entries.append(json.load(f))
    entries.sort(key=lambda e: e["key"])
    with open(os.path.join(src, "brands.json")) as f:
        brands = json.load(f)
    return entries, brands


def validate(catalog):
    errors, seen = [], set()
    if catalog.get("format") != 1:
        errors.append("format must be 1")
    for t in catalog.get("templates") or []:
        c = t.get("content") or {}
        key = "{}/{}".format(c.get("brand"), c.get("os_type"))
        if t.get("key") != key:
            errors.append("{}: key does not match brand/os_type".format(t.get("key")))
        if key in seen:
            errors.append("{}: duplicate".format(key))
        seen.add(key)
        if not isinstance(t.get("revision"), int) or t["revision"] < 1:
            errors.append("{}: revision".format(key))
        unknown = sorted(set(c) - set(KNOWN_FIELDS))
        if unknown:
            errors.append("{}: unknown fields {} (add them to CONTENT_FIELDS first)".format(key, unknown))
        missing = [f for f in KNOWN_FIELDS if f not in c]
        if missing:
            errors.append("{}: missing fields {} (write null for unused ones)".format(key, missing))
        for f in IDENTITY_FIELDS + MANAGED_FIELDS + ("protocol",):
            if not c.get(f):
                errors.append("{}: {} is empty".format(key, f))
        need = max([version_tuple(FIELD_MIN_APP_VERSION[f]) for f in c if f in FIELD_MIN_APP_VERSION and c[f] is not None]
                   or [(0,)])
        if version_tuple(t.get("min_app_version")) < need:
            errors.append("{}: min_app_version {} is lower than {} needed by its fields".format(
                key, t.get("min_app_version"), ".".join(map(str, need))))
        for what, p in regexes(c):
            try:
                re.compile(p)
            except re.error as e:
                errors.append("{}: {} {!r}: {}".format(key, what, p, e))
    return errors


def build(a):
    entries, brands = _load_src(a.src)
    prev = {}
    version = a.version
    if a.previous:
        with open(a.previous) as f:
            old = json.load(f)
        prev = {t["key"]: t for t in old["templates"]}
        version = version or old["catalog_version"] + 1
    for e in entries:
        p = prev.get(e["key"])
        if p and tracked_hash(p["content"]) != tracked_hash(e["content"]):
            e["revision"] = max(e["revision"], p["revision"] + 1)
            hashes = list(p.get("previous_hashes") or []) + list(e.get("previous_hashes") or []) + [content_hash(p["content"])]
            e["previous_hashes"] = sorted(set(hashes))
            e["previous_field_hashes"] = {f: list(v) for f, v in (p.get("previous_field_hashes") or {}).items()}
            add_field_hashes(e, p["content"])
        elif p:
            e["revision"] = p["revision"]
            e["previous_hashes"] = p.get("previous_hashes") or []
            e["previous_field_hashes"] = p.get("previous_field_hashes") or {}
        display = {b["brand"]: b["display_name"] for b in brands}
        e["brand_display_name"] = display.get(e["content"]["brand"])
    catalog = {"format": 1, "catalog_version": version or 1,
               "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "templates": entries, "brands": brands}
    errors = validate(catalog)
    if errors:
        sys.exit("invalid catalog:\n  " + "\n  ".join(errors))
    with open(a.out, "w") as f:
        json.dump(catalog, f, indent=1, sort_keys=True, ensure_ascii=False)
    print("catalog", catalog["catalog_version"], "with", len(entries), "templates ->", a.out)


def sign(a):
    with open(a.key, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(a.catalog, "rb") as f:
        data = f.read()
    sig = base64.b64encode(key.sign(data)).decode()
    with open(a.catalog + ".sig", "w") as f:
        f.write(sig + "\n")
    print("signed ->", a.catalog + ".sig")


def verify(a):
    with open(a.pub) as f:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(f.read().strip()))
    with open(a.catalog, "rb") as f:
        data = f.read()
    with open(a.catalog + ".sig") as f:
        pub.verify(base64.b64decode(f.read().strip()), data)
    errors = validate(json.loads(data))
    if errors:
        sys.exit("signature ok, catalog invalid:\n  " + "\n  ".join(errors))
    print("signature and catalog ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("keygen"); s.add_argument("--out", required=True); s.set_defaults(fn=keygen)
    s = sub.add_parser("export"); s.add_argument("--db", required=True); s.add_argument("--out", required=True); s.set_defaults(fn=export)
    s = sub.add_parser("build"); s.add_argument("--src", required=True); s.add_argument("--out", required=True)
    s.add_argument("--previous"); s.add_argument("--version", type=int); s.set_defaults(fn=build)
    s = sub.add_parser("sign"); s.add_argument("--key", required=True); s.add_argument("catalog"); s.set_defaults(fn=sign)
    s = sub.add_parser("verify"); s.add_argument("--pub", required=True); s.add_argument("catalog"); s.set_defaults(fn=verify)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
