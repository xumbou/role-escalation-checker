# -*- coding: utf-8 -*-
"""Moteur differentiel : rejoue chaque requete sous chaque profil -> matrice d'acces.

- En mode non-destructif, les verbes mutateurs ne sont PAS rejoues (securite par defaut).
- Concurrence optionnelle (network.max_workers) : une Session par cellule (l'amorcage
  CSRF est par-session, donc thread-safe).
"""
from concurrent.futures import ThreadPoolExecutor

import requests

from . import http as H

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _cell(cfg, req, profile, ev, label, kw):
    session = requests.Session()
    session.headers.update({"User-Agent": "bacscan"})
    return H.replay(session, cfg, req, profile, ev, label, **kw)


def build_matrix(cfg, requests_list, ev, **kw):
    """Renvoie [{request, by_profile: {nom: record}}] pour toutes les requetes."""
    matrix = [{"request": req, "by_profile": {}} for req in requests_list]
    jobs = []  # (row, profil_nom, req, profil, label)
    for i, req in enumerate(requests_list):
        mutating = req["method"] not in SAFE_METHODS
        for p in cfg.profiles:
            label = "matrix[%d]:%s" % (i, p.name)
            if mutating and not cfg.destructive:
                ev.log(label, req["method"], req["url"], p.name, None, 0,
                       note="skip mutating (non-destructif)")
                matrix[i]["by_profile"][p.name] = None
            else:
                jobs.append((i, p.name, req, p, label))

    workers = getattr(cfg, "max_workers", 1)
    if workers <= 1:
        for i, pn, req, p, label in jobs:
            matrix[i]["by_profile"][pn] = _cell(cfg, req, p, ev, label, kw)
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_cell, cfg, req, p, ev, label, kw): (i, pn)
                    for i, pn, req, p, label in jobs}
            for fut in futs:
                i, pn = futs[fut]
                matrix[i]["by_profile"][pn] = fut.result()
    return matrix
