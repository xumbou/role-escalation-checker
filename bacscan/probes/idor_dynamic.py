# -*- coding: utf-8 -*-
"""IDOR dynamique (chainage de requetes) :

  (1) Harvest : on rejoue les requetes GET sous l'attaquant, on extrait les IDs des
      reponses (listes sur-exposees), puis on accede aux objets DONT L'OWNER N'EST PAS
      l'attaquant -> 2xx = IDOR materialise.
  (2) Enumeration sequentielle : pour un dernier segment d'URL numerique, on essaie les
      voisins (id +/- N) -> 2xx = ressource d'autrui devinable.

Non destructif : GET uniquement.
"""
import json

import requests

from .. import http as H
from .. import oracles
from .. import harvest as HV

SAFE = {"GET", "HEAD", "OPTIONS"}


def _detail_url(coll_url, id_val):
    return coll_url.rstrip("/") + "/" + str(id_val)


def _neighbors(seg, rng):
    try:
        n = int(seg)
    except (ValueError, TypeError):
        return []
    return [str(n + d) for d in range(-rng, rng + 1) if d != 0 and n + d >= 0]


def run(cfg, requests_list, ev, **kw):
    attacker = cfg.attacker()
    if not attacker:
        return []
    s = requests.Session()
    s.headers.update({"User-Agent": "bacscan-idor-dyn"})
    my_uid = str(attacker.ids.get("userId") or attacker.ids.get("user") or "")
    rng = int(cfg.idor_dynamic.get("seq_range", 2))
    findings, seen = [], set()

    for req in requests_list:
        if req["method"] not in SAFE:
            continue
        url = req["url"]

        # (1) harvest depuis la reponse de l'attaquant
        rec = H.replay(s, cfg, req, attacker, ev, "dyn:list:%s" % url, **kw)
        if rec and oracles.is_success(rec) and rec.get("text"):
            try:
                items = HV.harvest(json.loads(rec["text"]))
            except ValueError:
                items = []
            for it in items:
                owner = it.get("owner")
                if owner and my_uid and owner == my_uid:
                    continue  # objet de l'attaquant lui-meme
                durl = _detail_url(url, it["val"])
                if durl in seen:
                    continue
                seen.add(durl)
                dr = H.replay(s, cfg, {"method": "GET", "url": durl, "headers": {},
                                       "body": None}, attacker, ev,
                              "dyn:obj:%s" % durl, **kw)
                if oracles.is_success(dr):
                    findings.append({
                        "type": "idor-dynamic", "severity": "high",
                        "cwe": "CWE-639", "owasp_api": "API1:2023",
                        "title": "IDOR dynamique: %s (owner=%s) accessible par %s"
                                 % (durl, owner, attacker.name),
                        "request": {"method": "GET", "url": durl},
                        "attacker": attacker.name, "evidence": dr})

        # (2) enumeration sequentielle sur le dernier segment
        base, _, last = url.rstrip("/").rpartition("/")
        for nb in _neighbors(last, rng):
            nurl = base + "/" + nb
            if nurl in seen:
                continue
            seen.add(nurl)
            nr = H.replay(s, cfg, {"method": "GET", "url": nurl, "headers": {},
                                   "body": None}, attacker, ev, "dyn:seq:%s" % nurl, **kw)
            if oracles.is_success(nr):
                findings.append({
                    "type": "idor-sequential", "severity": "high",
                    "cwe": "CWE-639", "owasp_api": "API1:2023",
                    "title": "IDOR sequentiel: %s accessible (voisin de %s)" % (nurl, last),
                    "request": {"method": "GET", "url": nurl},
                    "attacker": attacker.name, "evidence": nr})
    return findings
