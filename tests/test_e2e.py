# -*- coding: utf-8 -*-
"""Test e2e : demarre le mock vulnerable, execute bacscan, asserte la detection.

C'est la verification EMPIRIQUE de l'outil : si bacscan detecte la BOLA et confirme
l'escalade de role sur le mock, le pipeline complet fonctionne.
"""
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
    return {"log": {"entries": [
        {"request": {"method": "GET", "url": base + "/orgs/o-50/members",
                     "headers": [{"name": "Authorization", "value": "Bearer captured"}]}},
    ]}}


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        cfg = Config({
            "engagement": "test",
            "base_url": base,
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
            "probes": ["idor"],
            "impact_plugins": ["role_escalation"],
            "role_escalation": {
                "list_path": "/orgs/{resource}/members",
                "promote_path": "/orgs/{resource}/administrators/{user}",
                "rollback_path": "/orgs/{resource}/members/{user}",
            },
        })
        tmp = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8")
        json.dump(build_har(base), tmp)
        tmp.close()
        reqs = [r for r in ingest.from_har(tmp.name) if cfg.host_allowed(r["url"])]

        res = cli.run(cfg, reqs)
        findings = res["findings"]
        types = {f["type"] for f in findings}
        print("Findings:")
        print(json.dumps([{k: f.get(k) for k in ("type", "severity", "title")}
                          for f in findings], indent=2, ensure_ascii=False))

        assert "idor" in types, "IDOR/BOLA non detecte (acces cross-org attendu)"
        assert "privilege-escalation" in types, "Escalade de role non confirmee"
        assert "anonymous-access" not in types, "anon ne doit pas passer (mock -> 401)"

        # rollback effectif : u-1001 ne doit plus etre ADMINISTRATOR (le DELETE retire
        # le lien -> entree absente, comme removeAdministrator dans le cas reel)
        post = mock_server.Handler.state["o-50"].get("u-1001")
        assert post is None or post.get("role") != "ADMINISTRATOR", "rollback non applique"
    finally:
        httpd.shutdown()

    print("\nOK: bacscan detecte BOLA + confirme l'escalade de role, rollback applique.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
