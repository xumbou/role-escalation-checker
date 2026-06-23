# -*- coding: utf-8 -*-
"""Test e2e : mock vulnerable + bacscan ; asserte la detection de toutes les classes
(IDOR/BOLA, BFLA force-browse, BFLA asymetrie, BOPLA, existence leakage, escalade de role)."""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # racine repo -> import bacscan
sys.path.insert(0, HERE)                    # tests/ -> import mock_server

from bacscan.config import Config
from bacscan import cli, ingest
import mock_server


def build_har(base):
    auth = [{"name": "Authorization", "value": "Bearer captured"}]
    return {"log": {"entries": [
        {"request": {"method": "GET", "url": base + "/orgs/o-50/members", "headers": auth}},
        {"request": {"method": "GET", "url": base + "/orgs/o-50/settings", "headers": auth}},
        {"request": {"method": "GET", "url": base + "/secrets/s-1", "headers": auth}},
        {"request": {"method": "POST", "url": base + "/orgs/o-50/members", "headers": auth,
                     "postData": {"mimeType": "application/json",
                                  "text": json.dumps({"userId": "u-3003"})}}},
    ]}}


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        cfg = Config({
            "engagement": "test", "base_url": base,
            "scope": {"allow_hosts": ["127.0.0.1"]},
            "auth": {"header": "Authorization", "prefix": "Bearer "},
            "profiles": [
                {"name": "anon", "token": None},
                {"name": "low", "token": "low-token",
                 "ids": {"userId": "u-1001", "orgId": "o-50"}},
                {"name": "victim", "token": "victim-token",
                 "ids": {"userId": "u-2002", "orgId": "o-77"}},
            ],
            "safety": {"destructive": True, "rollback": "auto"},
            "probes": ["idor", "bfla", "bopla", "leakage"],
            "impact_plugins": ["role_escalation"],
            "role_escalation": {
                "list_path": "/orgs/{resource}/members",
                "promote_path": "/orgs/{resource}/administrators/{user}",
                "rollback_path": "/orgs/{resource}/members/{user}"},
        })
        tmp = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8")
        json.dump(build_har(base), tmp)
        tmp.close()
        reqs = [r for r in ingest.from_har(tmp.name) if cfg.host_allowed(r["url"])]

        res = cli.run(cfg, reqs)
        findings = res["findings"]
        types = {f["type"] for f in findings}
        print("Types detectes:", sorted(types))
        print(json.dumps([{k: f.get(k) for k in ("type", "severity", "title")}
                          for f in findings], indent=2, ensure_ascii=False))

        for expected in ("idor", "bfla", "bfla-asymmetry", "bopla",
                         "existence-leakage", "privilege-escalation"):
            assert expected in types, "non detecte: %s" % expected
        assert "anonymous-access" not in types, "anon ne doit pas passer (mock -> 401)"

        post = mock_server.Handler.state["o-50"].get("u-1001")
        assert post is None or post.get("role") != "ADMINISTRATOR", "rollback non applique"
    finally:
        httpd.shutdown()

    print("\nOK: idor + bfla + bfla-asymmetry + bopla + existence-leakage + privesc detectes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
