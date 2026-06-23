# -*- coding: utf-8 -*-
"""Authentification pluggable par profil : bearer, cookie, OAuth refresh, CSRF.

Un Authenticator sait :
  - apply()   : injecter les credentials (header/cookies) + un token CSRF sur les verbes mutateurs ;
  - refresh() : (oauth) rafraichir le token d'acces depuis un refresh_token, declenche sur 401.

Les valeurs ${VAR} sont resolues depuis l'environnement (ne jamais ecrire un secret en clair).
"""
import os

import requests


def _resolve(v):
    if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
        return os.environ.get(v[2:-1])
    return v


class Authenticator:
    def __init__(self, kind="none", header="Authorization", prefix="Bearer ",
                 token=None, cookies=None, refresh=None, csrf=None):
        self.kind = kind
        self.header = header
        self.prefix = prefix
        self.token = token
        self.cookies = cookies or {}
        self.refresh_spec = refresh or {}
        self.csrf = csrf or {}
        self._csrf_primed = False

    def is_anon(self):
        return self.kind == "none"

    def apply(self, session, headers, method, cfg):
        if self.kind in ("bearer", "oauth") and self.token:
            headers[self.header] = self.prefix + self.token
        if self.kind == "cookie":
            for k, v in self.cookies.items():
                session.cookies.set(k, v)
        if self.csrf:
            verbs = {m.upper() for m in self.csrf.get("methods",
                     ["POST", "PUT", "PATCH", "DELETE"])}
            if method.upper() in verbs:
                tok = self._csrf_token(session, cfg)
                if tok:
                    headers[self.csrf.get("header", "X-CSRF-Token")] = tok

    def _csrf_token(self, session, cfg):
        fetch_url = self.csrf.get("fetch_url")
        if fetch_url and not self._csrf_primed and cfg.host_allowed(fetch_url):
            h = {}
            if self.token:
                h[self.header] = self.prefix + self.token
            try:
                session.get(fetch_url, headers=h, timeout=15)
            except requests.RequestException:
                pass
            self._csrf_primed = True
        cookie_name = self.csrf.get("cookie")
        if cookie_name:
            return session.cookies.get(cookie_name)
        return self.csrf.get("token")

    def refresh(self, session, cfg):
        if self.kind != "oauth" or not self.refresh_spec:
            return False
        url = self.refresh_spec.get("url")
        if not url or not cfg.host_allowed(url):
            return False
        field = self.refresh_spec.get("refresh_field", "refresh_token")
        body = {field: self.refresh_spec.get("refresh_token")}
        body.update(self.refresh_spec.get("extra") or {})
        try:
            data = session.post(url, json=body, timeout=15).json()
        except (requests.RequestException, ValueError):
            return False
        tok = data.get(self.refresh_spec.get("token_field", "access_token"))
        if tok:
            self.token = tok
            return True
        return False


def anon():
    return Authenticator(kind="none")


def _csrf(spec):
    return dict(spec) if isinstance(spec, dict) else None


def _refresh(spec):
    if not isinstance(spec, dict):
        return None
    r = dict(spec)
    r["refresh_token"] = _resolve(r.get("refresh_token"))
    return r


def build(profile, global_auth):
    """Construit l'Authenticator d'un profil (format 'auth:' ou legacy 'token:')."""
    g_header = (global_auth or {}).get("header", "Authorization")
    g_prefix = (global_auth or {}).get("prefix", "Bearer ")
    spec = profile.get("auth")
    csrf = _csrf(profile.get("csrf"))
    if isinstance(spec, dict):
        kind = spec.get("type", "bearer")
        if kind == "none":
            return Authenticator(kind="none")
        return Authenticator(
            kind=kind,
            header=spec.get("header", g_header),
            prefix=spec.get("prefix", g_prefix),
            token=_resolve(spec.get("token")),
            cookies={k: _resolve(v) for k, v in (spec.get("cookies") or {}).items()},
            refresh=_refresh(spec.get("refresh")),
            csrf=csrf,
        )
    tok = _resolve(profile.get("token"))  # legacy
    if tok:
        return Authenticator(kind="bearer", header=g_header, prefix=g_prefix,
                             token=tok, csrf=csrf)
    return Authenticator(kind="none")
