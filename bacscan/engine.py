# -*- coding: utf-8 -*-
"""Moteur differentiel : rejoue chaque requete sous chaque profil -> matrice d'acces.

En mode non-destructif, les verbes mutateurs ne sont PAS rejoues (securite par defaut).
"""
import requests

from . import http as H

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def build_matrix(cfg, requests_list, ev, **kw):
    """Renvoie [{request, by_profile: {nom: record}}] pour toutes les requetes."""
    session = requests.Session()
    session.headers.update({"User-Agent": "bacscan"})
    matrix = []
    for i, req in enumerate(requests_list):
        row = {"request": req, "by_profile": {}}
        mutating = req["method"] not in SAFE_METHODS
        for p in cfg.profiles:
            label = "matrix[%d]:%s" % (i, p.name)
            if mutating and not cfg.destructive:
                ev.log(label, req["method"], req["url"], p.name, None, 0,
                       note="skip mutating (non-destructif)")
                row["by_profile"][p.name] = None
                continue
            row["by_profile"][p.name] = H.replay(session, cfg, req, p, ev, label, **kw)
        matrix.append(row)
    return matrix
