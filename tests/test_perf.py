# -*- coding: utf-8 -*-
"""Perf/echelle : concurrence (resultats identiques), cap global de requetes
(troncature EXPLICITE), pagination (suivi des liens 'next')."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli
import mock_server


def _base_cfg(base, **net):
    d = {"engagement": "perf", "base_url": base,
         "scope": {"allow_hosts": ["127.0.0.1"]},
         "auth": {"header": "Authorization", "prefix": "Bearer "},
         "profiles": [{"name": "anon", "token": None},
                      {"name": "low", "token": "low-token", "ids": {"userId": "u-1001"}}],
         "safety": {"destructive": False}, "probes": []}
    if net:
        d["network"] = net
    return d


def _reqs(base):
    # /profile -> excessive-data ; /public/banner -> anonymous-access ; + un 3e endpoint
    return [{"method": "GET", "url": base + p, "headers": {}, "body": None}
            for p in ["/profile", "/public/banner", "/orgs/o-50/members"]]


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        # 1) concurrence : meme resultat en sequentiel (1) et parallele (4)
        seq = cli.run(Config(_base_cfg(base, max_workers=1)), _reqs(base))
        par = cli.run(Config(_base_cfg(base, max_workers=4)), _reqs(base))
        ts = sorted(f["type"] for f in seq["findings"])
        tp = sorted(f["type"] for f in par["findings"])
        assert ts == tp and ts, ("concurrence != sequentiel", ts, tp)

        # 2) cap global : troncature EXPLICITE (note BUDGET_EXCEEDED)
        res = cli.run(Config(_base_cfg(base, max_requests=2, max_workers=1)), _reqs(base))
        assert any(e.get("note") == "BUDGET_EXCEEDED" for e in res["evidence"]), "cap non applique"

        # 3) pagination : un id present uniquement en page 2 est atteint
        cfgp = _base_cfg(base)
        cfgp["probes"] = ["idor_dynamic"]
        cfgp["idor_dynamic"] = {"max_pages": 2}
        resp = cli.run(Config(cfgp), [{"method": "GET", "url": base + "/plist",
                                       "headers": {}, "body": None}])
        urls = [(f.get("request") or {}).get("url", "") for f in resp["findings"]]
        assert any(u.endswith("/plist/d-9") for u in urls), ("pagination KO", urls)
    finally:
        httpd.shutdown()
    print("[OK] perf: concurrence coherente, cap explicite, pagination (next) suivie")
    return 0


if __name__ == "__main__":
    sys.exit(main())
