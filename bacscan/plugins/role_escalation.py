# -*- coding: utf-8 -*-
"""Plugin de confirmation d'impact : escalade de role (auto-promotion administrateur).

Le moteur/sonde signale un candidat ; ce plugin PROUVE l'effet metier reel :
promotion sous le profil attaquant -> verification que le role devient admin ->
rollback. C'est le pendant 'confirmation' du check autonome check_role_escalation.py.
NON DESTRUCTIF sauf safety.destructive=true (et rollback automatique ensuite).
"""
import json

import requests

from .. import http as H
from .. import oracles

DEFAULTS = {
    "list_path": "/{resource}/members",
    "promote_path": "/{resource}/administrators/{user}",
    "promote_method": "POST",
    "role_field": "role",
    "admin_role": "ADMINISTRATOR",
    "rollback_method": "DELETE",
    "rollback_path": "/{resource}/members/{user}",
}


def _render(tpl, resource, user):
    return tpl.replace("{resource}", str(resource)).replace("{user}", str(user))


def _find_role(data, user_id, role_field):
    uid = str(user_id)
    if isinstance(data, dict):
        items = data.get("members") or data.get("users") or data.get("results") or []
    elif isinstance(data, list):
        items = data
    else:
        items = []
    for e in items:
        if isinstance(e, dict) and uid in json.dumps(e, ensure_ascii=False):
            return e.get(role_field)
    return None


def run(cfg, ev, **kw):
    conf = dict(DEFAULTS)
    conf.update(cfg.plugin_conf.get("role_escalation", {}))
    attacker = cfg.attacker()
    if not attacker:
        return []
    resource = attacker.ids.get("orgId") or attacker.ids.get("resource")
    user = attacker.ids.get("userId") or attacker.ids.get("user")
    if not resource or not user:
        return []

    session = requests.Session()
    findings = []
    promote_url = cfg.base_url + _render(conf["promote_path"], resource, user)
    list_url = cfg.base_url + _render(conf["list_path"], resource, user)
    promote_req = {"method": conf["promote_method"], "url": promote_url,
                   "headers": {}, "body": ""}

    # Controle : promotion sans auth -> doit echouer (rend un 2xx significatif).
    from ..config import Profile
    from .. import auth as A
    H.replay(session, cfg, promote_req, Profile("_anon", A.anon()), ev,
             "role_esc:control_no_auth", **kw)

    if not cfg.destructive:
        ev.log("role_esc:skipped", conf["promote_method"], promote_url, attacker.name,
               None, 0, note="non-destructif: safety.destructive=true requis pour confirmer")
        return findings

    # Test vertical : promotion sous le profil attaquant.
    promo = H.replay(session, cfg, promote_req, attacker, ev, "role_esc:promote", **kw)
    if not oracles.is_success(promo):
        return findings  # le serveur a refuse -> finding refute

    # Impact : le role a-t-il reellement change ?
    list_req = {"method": "GET", "url": list_url, "headers": {}, "body": None}
    after = H.replay(session, cfg, list_req, attacker, ev, "role_esc:impact", **kw)
    role = None
    if after:
        try:
            role = _find_role(json.loads(after["text"]), user, conf["role_field"])
        except ValueError:
            pass
    is_admin = (role == conf["admin_role"])

    # Rollback (restauration de l'etat).
    if cfg.rollback:
        rb_req = {"method": conf["rollback_method"],
                  "url": cfg.base_url + _render(conf["rollback_path"], resource, user),
                  "headers": {}, "body": None}
        H.replay(session, cfg, rb_req, attacker, ev, "role_esc:rollback", **kw)

    if is_admin:
        findings.append({
            "type": "privilege-escalation", "severity": "critical",
            "confirmed_by": "plugin",
            "cwe": "CWE-269", "owasp_api": "API5:2023",
            "title": "Auto-promotion ADMINISTRATOR confirmee (role=%s materialise sur %s)"
                     % (role, resource),
            "request": {"method": conf["promote_method"], "url": promote_url},
            "attacker": attacker.name,
            "evidence": {"promote": promo, "impact": after},
        })
    return findings
