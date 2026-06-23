# -*- coding: utf-8 -*-
"""Verifie l'etage de triage : une detection NON exploitable est reclassee en faux
positif (avec raison) au lieu d'etre remontee, et le 'pourquoi' est journalise.

Scenario (sonde bfla force-browse sur 3 endpoints) :
  /admin/users   -> 200 authentifie, 401 anon          => CONFIRMED
  /public/banner -> 200 meme sans auth (publique)       => FALSE_POSITIVE (benign)
  /empty         -> 200 mais corps vide                 => INCONCLUSIVE (tool_limitation)
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli
import mock_server


def _verdict(findings, suffix):
    for f in findings:
        if (f.get("request") or {}).get("url", "").endswith(suffix):
            return f
    return None


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    logf = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
    try:
        cfg = Config({
            "engagement": "triage", "base_url": base,
            "scope": {"allow_hosts": ["127.0.0.1"]},
            "auth": {"header": "Authorization", "prefix": "Bearer "},
            "profiles": [{"name": "anon", "token": None},
                         {"name": "low", "token": "low-token",
                          "ids": {"userId": "u-1001", "orgId": "o-50"}}],
            "safety": {"destructive": False},
            "probes": ["bfla"],
            "bfla": {"wordlist": ["/admin/users", "/public/banner", "/empty"]},
            "output": {"triage_log": logf},
        })
        res = cli.run(cfg, [])
        f_admin = _verdict(res["findings"], "/admin/users")
        f_pub = _verdict(res["findings"], "/public/banner")
        f_empty = _verdict(res["findings"], "/empty")

        assert f_admin and f_admin["verdict"] == "confirmed", ("admin", f_admin)
        assert f_pub and f_pub["verdict"] == "false_positive" \
            and f_pub["triage"]["category"] == "benign", ("public", f_pub)
        assert f_empty and f_empty["verdict"] == "inconclusive" \
            and f_empty["triage"]["category"] == "tool_limitation", ("empty", f_empty)

        assert res["false_positives"] and res["inconclusive"]

        # le 'pourquoi' est journalise dans le fichier de log
        data = open(logf, encoding="utf-8").read()
        assert "FALSE_POSITIVE" in data, "log FP manquant"
        assert "publique" in data.lower(), "raison du FP non journalisee"
        assert "TRIAGE summary" in data, "synthese de triage manquante"
    finally:
        httpd.shutdown()
        try:
            os.unlink(logf)
        except OSError:
            pass

    print("[OK] triage: public->FP(benign), admin->confirmed, empty->inconclusive(tool_limitation); log ecrit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
