# -*- coding: utf-8 -*-
"""Moteur differentiel : rejoue chaque requete sous chaque profil -> matrice d'acces."""
import requests

from . import http as H


def build_matrix(cfg, requests_list, ev, **kw):
    """Renvoie [{request, by_profile: {nom: record}}] pour toutes les requetes."""
    session = requests.Session()
    session.headers.update({"User-Agent": "bacscan"})
    matrix = []
    for i, req in enumerate(requests_list):
        row = {"request": req, "by_profile": {}}
        for p in cfg.profiles:
            row["by_profile"][p.name] = H.replay(
                session, cfg, req, p, ev, "matrix[%d]:%s" % (i, p.name), **kw)
        matrix.append(row)
    return matrix
