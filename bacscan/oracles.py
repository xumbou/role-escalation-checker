# -*- coding: utf-8 -*-
"""Oracles de verdict (anti-faux-positifs), inspires de la recherche sur le fuzzing
REST guide par politique d'acces (oracles sur les status codes)."""
import json

# Champs dont la presence dans une reponse = exposition de donnees sensibles
SENSITIVE_HIGH = {
    "password", "passwd", "pwd", "secret", "client_secret", "token",
    "access_token", "refresh_token", "api_key", "apikey", "apitoken",
    "private_key", "privatekey", "ssn", "social_security", "credit_card",
    "card_number", "cardnumber", "cvv", "cvc", "pin",
}
SENSITIVE_LOW = {"email", "phone", "telephone", "dob", "date_of_birth",
                 "address", "iban", "passport"}


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


def _collect_keys(obj, found):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int, float)) and str(v) != "":
                found.add(k.lower())
            else:
                _collect_keys(v, found)
    elif isinstance(obj, list):
        for v in obj:
            _collect_keys(v, found)


def excessive_data(matrix, cfg):
    """Oracle 'excessive data exposure' (CWE-200 / API3:2023) : une reponse 2xx qui
    contient des champs sensibles (password, token, ssn...) -> exposition. Tourne sur
    la matrice deja collectee ; la cle reste detectable meme si la valeur est redactee."""
    out = []
    extra = {s.lower() for s in (getattr(cfg, "sensitive_fields", None) or [])}
    high = SENSITIVE_HIGH | extra
    attacker = cfg.attacker()
    aname = attacker.name if attacker else None
    for row in matrix:
        rec, who = None, None
        for cand in ("anon", aname):  # le profil le plus bas qui obtient un 2xx
            r = row["by_profile"].get(cand)
            if is_success(r):
                rec, who = r, cand
                break
        if not rec or not rec.get("text"):
            continue
        try:
            body = json.loads(rec["text"])
        except ValueError:
            continue
        keys = set()
        _collect_keys(body, keys)
        hits = sorted(keys & high) or sorted(keys & SENSITIVE_LOW)
        if hits:
            out.append({
                "type": "excessive-data-exposure",
                "severity": "high" if keys & high else "low",
                "cwe": "CWE-200", "owasp_api": "API3:2023",
                "title": "Donnees sensibles exposees (%s) au profil '%s': %s %s"
                         % (",".join(hits), who, row["request"]["method"],
                            row["request"]["url"]),
                "request": {"method": row["request"]["method"],
                            "url": row["request"]["url"]},
                "fields": hits, "evidence": rec,
            })
    return out
