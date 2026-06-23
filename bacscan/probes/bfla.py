# -*- coding: utf-8 -*-
"""Sonde BFLA (Broken Function Level Authorization).

  A) force-browse : un profil bas-privilege atteint-il un endpoint 'fonction privilegiee' ?
  B) verb-tampering + oracle d'asymetrie (arXiv) : si >=2 de {PUT,PATCH,DELETE} sont
     refuses (401/403) et au moins 1 reussit (2xx), l'autorisation au niveau fonction
     est incoherente.

Les verbes mutateurs (B) ne sont joues qu'avec safety.destructive=true.
"""
import requests

from .. import http as H
from .. import oracles

DEFAULT_WORDLIST = ["/admin", "/admin/users", "/internal", "/manage",
                    "/users", "/roles", "/config", "/settings"]
MUT_VERBS = ["PUT", "PATCH", "DELETE"]


def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": "bacscan-bfla"})
    return s


def run(cfg, requests_list, ev, **kw):
    attacker = cfg.attacker()
    if not attacker:
        return []
    s = _session()
    findings = []

    # A) force-browse d'endpoints "fonction privilegiee" (non destructif : GET)
    for path in (cfg.bfla.get("wordlist") or DEFAULT_WORDLIST):
        url = cfg.base_url + path
        req = {"method": "GET", "url": url, "headers": {}, "body": None}
        rec = H.replay(s, cfg, req, attacker, ev, "bfla:force-browse:%s" % path, **kw)
        if oracles.is_success(rec):
            findings.append({
                "type": "bfla", "severity": "high",
                "cwe": "CWE-285", "owasp_api": "API5:2023",
                "title": "BFLA force-browse: %s accessible par le profil %s"
                         % (url, attacker.name),
                "request": {"method": "GET", "url": url},
                "attacker": attacker.name, "evidence": rec,
            })

    # B) verb-tampering + asymetrie (mutateur -> gate destructive)
    if not cfg.destructive:
        ev.log("bfla:verb-tamper:skipped", "-", cfg.base_url, attacker.name, None, 0,
               note="non-destructif: safety.destructive=true requis")
        return findings

    seen = set()
    for req in requests_list:
        url = req["url"]
        if url in seen:
            continue
        seen.add(url)
        statuses = {}
        for verb in MUT_VERBS:
            vreq = {"method": verb, "url": url, "headers": {}, "body": req.get("body")}
            rec = H.replay(s, cfg, vreq, attacker, ev,
                           "bfla:verb:%s:%s" % (verb, url), **kw)
            statuses[verb] = rec["status"] if rec else None
        forbidden = [v for v, st in statuses.items() if st in (401, 403)]
        success = [v for v, st in statuses.items() if st in (200, 201, 202, 204)]
        if len(forbidden) >= 2 and success:
            findings.append({
                "type": "bfla-asymmetry", "severity": "high",
                "cwe": "CWE-285", "owasp_api": "API5:2023",
                "title": "BFLA asymetrie sur %s: %s refuse(s) mais %s autorise(s)"
                         % (url, "+".join(forbidden), "+".join(success)),
                "request": {"method": success[0], "url": url},
                "attacker": attacker.name, "evidence": statuses,
            })
    return findings
