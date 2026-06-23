# -*- coding: utf-8 -*-
"""Test `suggest` : auto-detection (JWT user-id, promote/list/admin/role-field) +
generation d'un engagement.yaml chargeable par config.load_config.

Fixtures 100% SYNTHETIQUES : host api.lab.local, JWT factice HS256 clef "test",
users bidon. Aucune donnee client.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan import suggest
from bacscan.config import Config

LAB_HOST = "api.lab.local"
LAB_BASE = "https://api.lab.local"


def _b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def fake_jwt(claims):
    """JWT factice signe HS256 clef 'test' (signature non verifiee par le decodeur)."""
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url(claims)
    sig = base64.urlsafe_b64encode(
        hmac.new(b"test", (header + "." + payload).encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return ".".join([header, payload, sig])


def build_fixture_har():
    jwt = fake_jwt({"sub": "u-1001", "preferred_username": "attacker", "iss": "lab"})
    auth = [{"name": "Authorization", "value": "Bearer " + jwt}]
    members_body = json.dumps({"members": [
        {"userId": "u-1001", "role": "MEMBER"},
        {"userId": "u-2002", "role": "ADMINISTRATOR"},
    ]})
    return {"log": {"version": "1.2", "creator": {"name": "test", "version": "1"},
                    "entries": [
        {"request": {"method": "GET", "url": LAB_BASE + "/orgs/o-50/members",
                     "headers": auth},
         "response": {"status": 200,
                      "content": {"mimeType": "application/json", "text": members_body}}},
        {"request": {"method": "POST", "url": LAB_BASE + "/orgs/o-50/administrators/u-1001",
                     "headers": auth, "postData": {"mimeType": "application/json", "text": ""}},
         "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}}},
        {"request": {"method": "GET", "url": LAB_BASE + "/health", "headers": []},
         "response": {"status": 200, "content": {"mimeType": "text/plain", "text": "ok"}}},
    ]}}


def main():
    tmp = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8")
    json.dump(build_fixture_har(), tmp)
    tmp.close()

    det = suggest.analyze(tmp.name)

    assert det["host"] == LAB_HOST, ("host", det["host"])
    assert det["base_url"] == LAB_BASE, ("base_url", det["base_url"])

    # user-id depuis le JWT (claim 'sub')
    assert det["profiles"], "aucun profil/token detecte"
    assert det["profiles"][0]["user_id"] == "u-1001", ("user_id", det["profiles"][0])
    assert det["profiles"][0]["user_id_claim"] == "sub", det["profiles"][0]

    # promote_path templatise : POST .../administrators/<id>
    assert det["promote_path"] == "/orgs/{resource}/administrators/{user}", \
        ("promote_path", det["promote_path"])
    # list_path templatise : GET .../members (corps = liste a role)
    assert det["list_path"] == "/orgs/{resource}/members", ("list_path", det["list_path"])
    # role-field + admin-role depuis la reponse JSON
    assert det["admin_role"] == "ADMINISTRATOR", ("admin_role", det["admin_role"])
    assert det["role_field"] == "role", ("role_field", det["role_field"])

    # Regression : les segments de version d'API (v1, v2...) ne sont PAS des ids
    assert not suggest._is_id_segment("v1") and not suggest._is_id_segment("v2"), \
        "v1/v2 ne doivent pas etre traites comme des segments-id"
    assert suggest.templatize_path("/api/v1/orgs/o-50/members") == \
        "/api/v1/orgs/{resource}/members", \
        suggest.templatize_path("/api/v1/orgs/o-50/members")
    assert suggest.templatize_path("/api/v2/orgs/o-50/administrators/u-1001") == \
        "/api/v2/orgs/{resource}/administrators/{user}", \
        suggest.templatize_path("/api/v2/orgs/o-50/administrators/u-1001")

    # Le YAML genere doit etre chargeable par config.load_config
    out = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    out.close()
    cfg = suggest.write_engagement(det, out.name, engagement="lab-assisted")
    assert isinstance(cfg, Config)
    assert cfg.base_url == LAB_BASE, cfg.base_url
    assert LAB_HOST in cfg.allow_hosts, cfg.allow_hosts
    assert not cfg.destructive, "safety.destructive doit etre False"
    assert "role_escalation" in cfg.impact_plugins
    re_conf = cfg.plugin_conf.get("role_escalation", {})
    assert re_conf.get("admin_role") == "ADMINISTRATOR", re_conf
    assert re_conf.get("role_field") == "role", re_conf
    assert re_conf.get("promote_path") == "/orgs/{resource}/administrators/{user}", re_conf
    assert re_conf.get("list_path") == "/orgs/{resource}/members", re_conf

    # En-tete d'avertissement secrets present dans le fichier
    text = open(out.name, encoding="utf-8").read()
    assert "NE PAS COMMITTER" in text, "avertissement secrets manquant"

    # Le recap ne doit JAMAIS afficher le JWT en clair (redaction bearer)
    recap = suggest.format_recap(det)
    assert "eyJ" not in recap or "REDACTED" in recap, "JWT potentiellement en clair dans le recap"

    os.unlink(tmp.name)
    os.unlink(out.name)
    print("[OK] suggest: user-id JWT + promote/list/admin/role-field detectes, YAML valide")
    return 0


if __name__ == "__main__":
    sys.exit(main())
