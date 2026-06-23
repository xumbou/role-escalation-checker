# -*- coding: utf-8 -*-
"""Couplage statique -> dynamique.

Ingere un `access_matrix.json` produit par une analyse statique du code (matrice des
endpoints + classification de garde) et genere des requetes CANDIDATES a tester en
priorite : celles sans garde serveur detectee ou a garde client seulement, et/ou
privilegiees. Ce fichier n'est lu QUE localement, jamais committe.

Format attendu (tolerant) :
    {"matrix": [{"path": "/x/{id}", "methods": ["GET","POST"],
                 "privileged": true, "guard_class": "AUCUNE garde detectee"}, ...]}

Heuristique de risque : pas de marqueur de garde serveur dans guard_class, OU endpoint
privilegie. (Le marqueur par defaut "serveur" couvre la taxonomie FR
"garde serveur probable" ; ajuster server_guard_mark au besoin.)
"""
import json


def load_candidates(path, base_url, server_guard_mark="serveur"):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = data.get("matrix", []) if isinstance(data, dict) else (data or [])
    base = (base_url or "").rstrip("/")
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        guard = (r.get("guard_class") or "").lower()
        risky = server_guard_mark not in guard  # aucune garde serveur detectee
        if not (risky or r.get("privileged")):
            continue
        p = r.get("path") or ""
        if not p:
            continue
        url = p if p.startswith("http") else base + "/" + p.lstrip("/")
        for m in (r.get("methods") or ["GET"]):
            out.append({
                "method": str(m).upper(), "url": url, "headers": {}, "body": None,
                "content_type": None,
                "_static": {"guard": r.get("guard_class"),
                            "privileged": bool(r.get("privileged"))},
            })
    return out
