# -*- coding: utf-8 -*-
"""Non-regression du CAS D'ORIGINE (auto-nomination admin) apres l'evolution de l'outil :

  - promotion par POST SANS corps ;
  - role confirme dans une reponse a CLE DE LISTE METIER CUSTOM (non standard) ;
  - champ de role NON standard (role_field configurable).

Verifie que les DEUX outils gerent encore cette forme :
  A) le check autonome tools/check_role_escalation.py (parsing) ;
  B) le plugin de confirmation de bacscan (bout en bout contre un mock a cette forme).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from bacscan.config import Config
from bacscan import cli
import mock_server
import check_role_escalation as cre


def test_standalone_parser():
    # reponse encapsulee dans une cle metier custom + champ de role non standard
    data = {"grants": [{"principal": "u-me", "privilege": "ADMINISTRATOR"}]}
    entries = cre.normalize_members(data)
    present, role = cre.find_caller_role(entries, "u-me", "privilege")
    assert present and role == "ADMINISTRATOR", ("standalone parser", present, role)


def test_bacscan_plugin(base):
    cfg = Config({
        "engagement": "origin-case", "base_url": base,
        "scope": {"allow_hosts": ["127.0.0.1"]},
        "auth": {"header": "Authorization", "prefix": "Bearer "},
        "profiles": [
            {"name": "anon", "token": None},
            {"name": "low", "token": "low-token",
             "ids": {"resource": "o-mine", "userId": "u-me"}}],
        "safety": {"destructive": True, "rollback": "auto"},
        "impact_plugins": ["role_escalation"],
        "role_escalation": {
            "promote_path": "/svc/orgs/{resource}/admins/{user}",   # POST sans corps
            "list_path": "/svc/orgs/{resource}/grants",             # cle de liste custom
            "role_field": "privilege",                              # champ de role non standard
            "rollback_method": "DELETE",
            "rollback_path": "/svc/orgs/{resource}/grants/{user}"},
    })
    res = cli.run(cfg, [])
    pe = [f for f in res["confirmed"] if f["type"] == "privilege-escalation"]
    assert pe, ("escalade non confirmee", [f.get("type") for f in res["findings"]])


def main():
    test_standalone_parser()
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        test_bacscan_plugin(base)
    finally:
        httpd.shutdown()
    print("[OK] cas d'origine couvert : check autonome (parsing) + bacscan (bout en bout)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
