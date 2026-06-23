# -*- coding: utf-8 -*-
"""Sonde BOPLA / mass-assignment (CWE-915 / API3:2023).

Pour les requetes a corps JSON, on ajoute des champs privilegies (role, isAdmin...)
et on rejoue sous le profil attaquant. Si la reponse 2xx reflete un champ injecte,
l'API accepte une affectation de propriete non autorisee.

Mutateur -> safety.destructive=true requis.
"""
import json

import requests

from .. import http as H
from .. import oracles

DEFAULT_FIELDS = {"role": "ADMINISTRATOR", "isAdmin": True, "admin": True}


def run(cfg, requests_list, ev, **kw):
    attacker = cfg.attacker()
    if not attacker:
        return []
    if not cfg.destructive:
        ev.log("bopla:skipped", "-", cfg.base_url, attacker.name, None, 0,
               note="non-destructif: safety.destructive=true requis")
        return []
    fields = cfg.bopla.get("inject_fields") or DEFAULT_FIELDS
    s = requests.Session()
    s.headers.update({"User-Agent": "bacscan-bopla"})
    findings = []
    for req in requests_list:
        if req["method"] not in ("POST", "PUT", "PATCH"):
            continue
        body = req.get("body")
        try:
            obj = json.loads(body) if isinstance(body, str) else (
                body if isinstance(body, dict) else None)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            continue
        tampered = dict(obj)
        tampered.update(fields)
        rec = H.replay(s, cfg, req, attacker, ev, "bopla:%s" % req["url"],
                       body_override=tampered, **kw)
        if oracles.is_success(rec) and rec.get("text"):
            reflected = [k for k, v in fields.items()
                         if ('"%s"' % k) in rec["text"] and str(v) in rec["text"]]
            if reflected:
                findings.append({
                    "type": "bopla", "severity": "high",
                    "cwe": "CWE-915", "owasp_api": "API3:2023",
                    "title": "BOPLA mass-assignment sur %s %s: champ(s) %s accepte(s)"
                             % (req["method"], req["url"], ",".join(reflected)),
                    "request": {"method": req["method"], "url": req["url"]},
                    "attacker": attacker.name, "evidence": rec,
                })
    return findings
