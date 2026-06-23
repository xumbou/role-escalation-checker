# -*- coding: utf-8 -*-
"""Verifie le durcissement : retry 429, suivi de redirection, erreurs explicites
(pas de None muet), redaction PII, journal d'audit horodate."""
import json
import os
import sys
import tempfile

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import http as H, report
from bacscan.http import Evidence
from bacscan.redact import redact
import mock_server


def _cfg(base, **net):
    d = {"engagement": "hard", "base_url": base,
         "scope": {"allow_hosts": ["127.0.0.1"]},
         "auth": {"header": "Authorization", "prefix": "Bearer "},
         "profiles": [{"name": "low", "token": "low-token-secret-123"}],
         "safety": {"destructive": False}}
    if net:
        d["network"] = net
    return Config(d)


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        cfg = _cfg(base)
        s = requests.Session()
        ev = Evidence()
        low = cfg.profile("low")

        # 1) retry sur 429 (Retry-After: 0) -> succes au 2e essai
        rec = H.replay(s, cfg, {"method": "GET", "url": base + "/flaky429",
                                "headers": {}, "body": None}, low, ev, "t")
        assert rec and rec["status"] == 200, ("429 retry", rec)

        # 2) suivi de redirection (302 -> 200)
        rec = H.replay(s, cfg, {"method": "GET", "url": base + "/redirect",
                                "headers": {}, "body": None}, low, ev, "t")
        assert rec and rec["status"] == 200, ("redirect", rec)

        # 3) erreur reseau EXPLICITE (port ferme) : record status=None + error, pas None muet
        cfg_err = _cfg("http://127.0.0.1:1", max_retries=0)
        rec = H.replay(s, cfg_err, {"method": "GET", "url": "http://127.0.0.1:1/x",
                                    "headers": {}, "body": None},
                       cfg_err.profile("low"), ev, "t")
        assert rec is not None and rec["status"] is None and rec.get("error"), ("explicit error", rec)

        # 4) redaction : email + password masques, marqueur fonctionnel conserve, secret masque
        r = redact('{"email":"a@b.com","password":"hunter2","role":"ADMINISTRATOR",'
                   '"tok":"low-token-secret-123"}', secrets=["low-token-secret-123"])
        assert "a@b.com" not in r and "hunter2" not in r, ("pii non masquee", r)
        assert "low-token-secret-123" not in r, ("secret non masque", r)
        assert "ADMINISTRATOR" in r, ("marqueur fonctionnel perdu", r)

        # 5) journal d'audit horodate
        logf = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        report.write_audit(ev.events, logf)
        data = json.load(open(logf, encoding="utf-8"))
        assert data["events"] and "timestamp" in data["events"][0], "audit sans horodatage"
        os.unlink(logf)
    finally:
        httpd.shutdown()

    print("[OK] hardening: retry 429, redirect, erreur explicite, redaction PII, audit horodate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
