# -*- coding: utf-8 -*-
"""Oracles de verdict (anti-faux-positifs), inspires de la recherche sur le fuzzing
REST guide par politique d'acces (oracles sur les status codes)."""


def is_success(rec):
    return rec is not None and rec["status"] in (200, 201, 202, 204)


def is_denied(rec):
    return rec is not None and rec["status"] in (401, 403)


def anonymous_access(matrix):
    """Oracle 'anonymous access' : une requete qui reussit (2xx) sous le profil anon
    = controle d'authentification absent (CWE-306)."""
    out = []
    for row in matrix:
        rec = row["by_profile"].get("anon")
        if is_success(rec):
            out.append({
                "type": "anonymous-access", "severity": "high",
                "cwe": "CWE-306", "owasp_api": "API2:2023",
                "title": "Acces anonyme accepte: %s %s"
                         % (row["request"]["method"], row["request"]["url"]),
                "request": {"method": row["request"]["method"],
                            "url": row["request"]["url"]},
                "evidence": rec,
            })
    return out
