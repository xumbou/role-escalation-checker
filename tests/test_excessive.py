# -*- coding: utf-8 -*-
"""Sonde excessive-data-exposure : detecte des champs sensibles dans une reponse 2xx
servie a un profil bas-privilege (le gap revele par VAmPI). La valeur reste redactee."""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli, ingest
import mock_server


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        cfg = Config({
            "engagement": "exc", "base_url": base,
            "scope": {"allow_hosts": ["127.0.0.1"]},
            "auth": {"header": "Authorization", "prefix": "Bearer "},
            "profiles": [{"name": "anon", "token": None},
                         {"name": "low", "token": "low-token", "ids": {"userId": "u-1001"}}],
            "safety": {"destructive": False, "redact": True},
            "probes": [],
        })
        har = {"log": {"entries": [{"request": {
            "method": "GET", "url": base + "/profile",
            "headers": [{"name": "Authorization", "value": "Bearer captured"}]}}]}}
        tmp = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8")
        json.dump(har, tmp)
        tmp.close()
        reqs = [r for r in ingest.from_har(tmp.name) if cfg.host_allowed(r["url"])]
        res = cli.run(cfg, reqs)

        exc = [f for f in res["findings"] if f["type"] == "excessive-data-exposure"]
        assert exc, ("non detecte", [f["type"] for f in res["findings"]])
        f = exc[0]
        assert f["severity"] == "high", f
        assert "password" in f["fields"] and "apikey" in f["fields"], f["fields"]
        assert f["verdict"] == "confirmed", f.get("verdict")
        # la valeur reelle ne doit PAS fuiter (redactee)
        assert "pass1" not in json.dumps(f["evidence"]), "valeur sensible non redactee"
        # anonymous-access NE doit PAS exister (l'endpoint exige une auth -> anon 401)
        assert not [x for x in res["findings"]
                    if x["type"] == "anonymous-access" and "/profile" in x["request"]["url"]]
    finally:
        httpd.shutdown()
    print("[OK] excessive-data-exposure: champs sensibles detectes (valeur redactee), profil authentifie")
    return 0


if __name__ == "__main__":
    sys.exit(main())
