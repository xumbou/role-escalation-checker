# -*- coding: utf-8 -*-
"""Dedup (doublons stricts supprimes) + grouping optionnel des types bruyants
(broken-auth qui allume chaque endpoint -> 1 finding agrege)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli
import mock_server


def _cfg(base, group):
    return Config({
        "engagement": "dedup", "base_url": base,
        "scope": {"allow_hosts": ["127.0.0.1"]},
        "auth": {"header": "Authorization", "prefix": "Bearer "},
        "profiles": [{"name": "anon", "token": None},
                     {"name": "low", "token": "low-token"}],
        "safety": {"destructive": False},
        "probes": [], "group_findings": group,
    })


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        # 2 endpoints accessibles a l'anon (public/banner ; flaky429 repond 200 apres retry)
        pub = [{"method": "GET", "url": base + p, "headers": {}, "body": None}
               for p in ["/public/banner", "/flaky429"]]
        # doublon strict : la meme URL captee 2 fois
        reqs = [{"method": "GET", "url": base + "/public/banner", "headers": {}, "body": None},
                {"method": "GET", "url": base + "/public/banner", "headers": {}, "body": None}]

        # sans grouping : le doublon strict est supprime -> 1 seul anonymous-access
        res = cli.run(_cfg(base, group=False), reqs)
        aa = [f for f in res["findings"] if f["type"] == "anonymous-access"]
        assert len(aa) == 1, ("dedup KO", len(aa))

        # avec grouping : 2 endpoints publics distincts -> 1 finding agrege
        res2 = cli.run(_cfg(base, group=True), pub)
        aa2 = [f for f in res2["findings"] if f["type"] == "anonymous-access"]
        assert len(aa2) == 1 and aa2[0].get("grouped_urls"), ("grouping KO", aa2)
        assert len(aa2[0]["grouped_urls"]) == 2, aa2[0].get("grouped_urls")
    finally:
        httpd.shutdown()
    print("[OK] dedup (doublon strict supprime) + grouping (N endpoints -> 1 finding agrege)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
