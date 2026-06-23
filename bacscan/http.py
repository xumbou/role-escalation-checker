# -*- coding: utf-8 -*-
"""Wrapper HTTP : rejeu d'une requete sous un profil donne + journal de preuves.

- Strip des en-tetes sensibles captures (auth/cookie) puis injection du profil.
- Garde-fou de scope a chaque appel.
"""
import hashlib
import time

import requests

SENSITIVE_HEADERS = {"authorization", "cookie", "x-csrf-token", "x-xsrf-token"}


class Evidence:
    """Journal des requetes/reponses (preuves)."""

    def __init__(self):
        self.events = []

    def log(self, label, method, url, profile, status, length, note=""):
        self.events.append({
            "label": label, "method": method, "url": url,
            "profile": profile, "status": status, "length": length, "note": note,
        })


def _clean_headers(headers):
    return {k: v for k, v in (headers or {}).items()
            if k.lower() not in SENSITIVE_HEADERS}


def replay(session, cfg, req, profile, ev, label,
           url_override=None, body_override=None, timeout=20, insecure=False):
    """Rejoue `req` sous `profile`. Renvoie un record de reponse ou None."""
    url = url_override or req["url"]
    if not cfg.host_allowed(url):
        ev.log(label, req["method"], url, profile.name, None, 0, note="SCOPE_BLOCKED")
        return None
    headers = _clean_headers(req.get("headers"))
    if profile.token:
        headers[cfg.auth_header] = cfg.auth_prefix + profile.token
    body = body_override if body_override is not None else req.get("body")
    if cfg.rate_limit_rps:
        time.sleep(1.0 / cfg.rate_limit_rps)
    try:
        resp = session.request(
            req["method"], url, headers=headers,
            data=body if isinstance(body, (str, bytes)) else None,
            json=body if isinstance(body, (dict, list)) else None,
            timeout=timeout, verify=not insecure)
    except requests.RequestException as exc:
        ev.log(label, req["method"], url, profile.name, None, 0, note="ERR:%s" % exc)
        return None
    text = resp.text or ""
    rec = {
        "status": resp.status_code,
        "length": len(text),
        "body_hash": hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12],
        "text": text[:5000],
        "url": url, "profile": profile.name, "method": req["method"],
    }
    ev.log(label, req["method"], url, profile.name, resp.status_code, len(text))
    return rec
