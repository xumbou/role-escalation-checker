# -*- coding: utf-8 -*-
"""GraphQL BFLA : une mutation captee est rejouee SANS authentification ; si elle
reussit -> autorisation de fonction cassee (CWE-285 / API5:2023)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli
import mock_server


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        cfg = Config({
            "engagement": "gqlbfla", "base_url": base,
            "scope": {"allow_hosts": ["127.0.0.1"]},
            "auth": {"header": "Authorization", "prefix": "Bearer "},
            "profiles": [{"name": "anon", "token": None},
                         {"name": "low", "token": "low-token", "ids": {"userId": "u-1"}}],
            "safety": {"destructive": True},
            "probes": ["graphql"],
        })
        reqs = [{"method": "POST", "url": base + "/graphql",
                 "content_type": "application/json",
                 "body": json.dumps({"query": "mutation { promoteUser(id: 1) { ok } }"})}]
        types = {f["type"] for f in cli.run(cfg, reqs)["findings"]}
        assert "graphql-bfla" in types, ("mutation sans auth non detectee", types)
    finally:
        httpd.shutdown()
    print("[OK] GraphQL BFLA: mutation executable sans authentification detectee")
    return 0


if __name__ == "__main__":
    sys.exit(main())
