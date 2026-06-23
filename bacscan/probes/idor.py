# -*- coding: utf-8 -*-
"""Sonde IDOR/BOLA : substitution d'identifiants cross-profil.

Pour chaque requete captee contenant un id appartenant au profil attaquant,
on substitue l'id homologue d'un autre profil (victime) et on rejoue sous le
token de l'attaquant. Un 2xx = acces a la ressource d'autrui (CWE-639 / API1:2023).
"""
import requests

from .. import http as H
from .. import oracles


def _swap(text, old, new):
    return text.replace(old, new) if text else text


def run(cfg, requests_list, ev, **kw):
    attacker = cfg.attacker()
    if not attacker or not attacker.ids:
        return []
    session = requests.Session()
    session.headers.update({"User-Agent": "bacscan-idor"})
    others = [p for p in cfg.profiles if p is not attacker and p.ids]
    findings = []
    for i, req in enumerate(requests_list):
        url = req["url"]
        body = req["body"] if isinstance(req.get("body"), str) else None
        for key, my_val in attacker.ids.items():
            my_val = str(my_val)
            in_url, in_body = (my_val in url), bool(body and my_val in body)
            if not (in_url or in_body):
                continue
            for victim in others:
                v_val = victim.ids.get(key)
                if not v_val or str(v_val) == my_val:
                    continue
                v_val = str(v_val)
                var_url = _swap(url, my_val, v_val) if in_url else url
                var_body = _swap(body, my_val, v_val) if in_body else req.get("body")
                rec = H.replay(session, cfg, req, attacker, ev,
                               "idor[%d]:%s:%s->%s" % (i, key, my_val, v_val),
                               url_override=var_url, body_override=var_body, **kw)
                if oracles.is_success(rec):
                    findings.append({
                        "type": "idor", "severity": "high",
                        "cwe": "CWE-639", "owasp_api": "API1:2023",
                        "title": "IDOR/BOLA: %s %s accessible (%s %s->%s, profil %s)"
                                 % (req["method"], var_url, key, my_val, v_val,
                                    attacker.name),
                        "request": {"method": req["method"], "url": var_url},
                        "attacker": attacker.name, "victim": victim.name,
                        "evidence": rec,
                    })
    return findings
