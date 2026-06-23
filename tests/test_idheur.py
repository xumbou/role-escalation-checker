# -*- coding: utf-8 -*-
"""Heuristiques d'ID enrichies : enumeration d'IDs ENCODES (base64 d'un entier) et
HASHES (md5 d'un entier crackable), + cles metier dans le harvest."""
import base64
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli, harvest
import mock_server


def _b64(n):
    return base64.urlsafe_b64encode(str(n).encode()).decode().rstrip("=")


def main():
    # harvest : cle metier (slug) + valeur UUID captees
    items = harvest.harvest({"items": [
        {"slug": "abc", "owner": "u-2"},
        {"ref_x": "550e8400-e29b-41d4-a716-446655440000"}]})
    keys = {it["key"] for it in items}
    assert "slug" in keys, ("cle metier non captee", keys)

    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        cfg = Config({
            "engagement": "idheur", "base_url": base,
            "scope": {"allow_hosts": ["127.0.0.1"]},
            "auth": {"header": "Authorization", "prefix": "Bearer "},
            "profiles": [{"name": "anon", "token": None},
                         {"name": "low", "token": "low-token", "ids": {"userId": "u-1001"}}],
            "safety": {"destructive": False},
            "probes": ["idor_dynamic"],
            "idor_dynamic": {"hash_crack_max": 200},
        })
        # trafic legitime : l'attaquant accede a SES objets (id 7) encode/hashe
        reqs = [{"method": "GET", "url": base + "/e/" + _b64(7), "headers": {}, "body": None},
                {"method": "GET", "url": base + "/h/" + hashlib.md5(b"7").hexdigest(),
                 "headers": {}, "body": None}]
        types = {f["type"] for f in cli.run(cfg, reqs)["findings"]}
        assert "idor-encoded" in types, ("base64 enum KO", types)
        assert "idor-hashed" in types, ("md5 crack+enum KO", types)
    finally:
        httpd.shutdown()
    print("[OK] ID heuristics: base64-int + md5-int crackable enumeres, cles metier captees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
