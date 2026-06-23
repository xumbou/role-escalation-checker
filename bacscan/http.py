# -*- coding: utf-8 -*-
"""Wrapper HTTP robuste : rejeu sous profil + journal de preuves horodate.

- injection des credentials via l'authenticator (refresh sur 401) ;
- retries sur 429 (Retry-After) / 5xx / erreurs reseau transitoires ;
- erreurs EXPLICITES (record status=None + champ 'error') au lieu d'un None muet ;
- suivi des redirections (note si la cible quitte le scope) ;
- redaction des donnees sensibles dans le corps stocke.
"""
import hashlib
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from .redact import redact

SENSITIVE_HEADERS = {"authorization", "cookie", "x-csrf-token", "x-xsrf-token"}
RETRY_STATUS = (429, 500, 502, 503, 504)


class Evidence:
    """Journal horodate des requetes/reponses (preuves + audit)."""

    def __init__(self):
        self.events = []

    def log(self, label, method, url, profile, status, length, note=""):
        self.events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "label": label, "method": method, "url": url,
            "profile": profile, "status": status, "length": length, "note": note,
        })


def _clean_headers(headers):
    return {k: v for k, v in (headers or {}).items()
            if k.lower() not in SENSITIVE_HEADERS}


def _backoff(cfg, attempt):
    base = getattr(cfg, "retry_backoff", 0.5)
    return min(base * (2 ** attempt), getattr(cfg, "retry_backoff_max", 8))


def _retry_after(resp, cfg, attempt):
    ra = resp.headers.get("Retry-After")
    if ra:
        try:
            return min(float(ra), getattr(cfg, "retry_backoff_max", 8))
        except ValueError:
            pass
    return _backoff(cfg, attempt)


def _send(session, cfg, req, profile, url, method, body, timeout, insecure):
    headers = _clean_headers(req.get("headers"))
    profile.auth.apply(session, headers, method, cfg)
    if cfg.rate_limit_rps:
        time.sleep(1.0 / cfg.rate_limit_rps)
    return session.request(
        method, url, headers=headers,
        data=body if isinstance(body, (str, bytes)) else None,
        json=body if isinstance(body, (dict, list)) else None,
        timeout=timeout, verify=not insecure, allow_redirects=True)


def _record(cfg, resp, url, profile, method, ev, label):
    text = resp.text or ""
    if getattr(cfg, "redact", True):
        text = redact(text, getattr(cfg, "secrets", ()))
    note = ""
    if (urlsplit(resp.url).hostname or "") and not cfg.host_allowed(resp.url):
        note = "REDIRECT_OUT_OF_SCOPE:%s" % resp.url
    rec = {"status": resp.status_code, "length": len(text),
           "body_hash": hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12],
           "text": text[:5000], "url": url, "final_url": resp.url,
           "profile": profile.name, "method": method, "error": None}
    ev.log(label, method, url, profile.name, resp.status_code, len(text), note=note)
    return rec


def replay(session, cfg, req, profile, ev, label,
           url_override=None, body_override=None, timeout=20, insecure=False):
    """Rejoue `req` sous `profile`. Renvoie un record (status=None+error si echec reseau)
    ou None si hors scope."""
    url = url_override or req["url"]
    if not cfg.host_allowed(url):
        ev.log(label, req["method"], url, profile.name, None, 0, note="SCOPE_BLOCKED")
        return None
    method = req["method"]
    body = body_override if body_override is not None else req.get("body")
    max_retries = getattr(cfg, "max_retries", 2)
    refreshed = False
    resp = None

    for attempt in range(max_retries + 1):
        try:
            resp = _send(session, cfg, req, profile, url, method, body, timeout, insecure)
        except requests.RequestException as exc:
            if attempt < max_retries:
                ev.log(label, method, url, profile.name, None, 0, note="retry(net):%s" % exc)
                time.sleep(_backoff(cfg, attempt))
                continue
            ev.log(label, method, url, profile.name, None, 0, note="ERR:%s" % exc)
            return {"status": None, "length": 0, "body_hash": "", "text": "",
                    "url": url, "final_url": url, "profile": profile.name,
                    "method": method, "error": str(exc)}
        if resp.status_code == 401 and not refreshed and profile.auth.refresh(session, cfg):
            refreshed = True
            continue  # re-essai immediat avec le token rafraichi
        if resp.status_code in RETRY_STATUS and attempt < max_retries:
            wait = _retry_after(resp, cfg, attempt)
            ev.log(label, method, url, profile.name, resp.status_code, 0,
                   note="retry(%d) in %.1fs" % (resp.status_code, wait))
            time.sleep(wait)
            continue
        return _record(cfg, resp, url, profile, method, ev, label)

    return _record(cfg, resp, url, profile, method, ev, label)
