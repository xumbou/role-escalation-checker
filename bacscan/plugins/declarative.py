# -*- coding: utf-8 -*-
"""Plugins de confirmation DECLARATIFS (YAML) : etapes + validation + rollback,
sans ecrire de code Python. Permet d'ajouter une preuve d'impact par mission.

Spec (dans le YAML d'engagement, cle 'declarative_plugins') :
  - name: role-escalation
    requires: { destructive: true }
    steps:
      - { id: promote, method: POST, url: "{base}/orgs/{orgId}/administrators/{userId}", as: low }
      - { id: check,   method: GET,  url: "{base}/orgs/{orgId}/members", as: low }
    validate: { step: check, status_success: true, contains: 'ADMINISTRATOR' }
    rollback:
      - { method: DELETE, url: "{base}/orgs/{orgId}/members/{userId}", as: low }
    severity: critical
    cwe: CWE-269
    owasp_api: API5:2023

Placeholders : {base} + tous les ids du profil attaquant (+ alias resource/user).
"""
import requests

from .. import http as H
from .. import auth as A
from ..config import Profile

SUCCESS = (200, 201, 202, 204)


def _ctx(cfg, attacker):
    ids = dict(attacker.ids) if attacker else {}
    ctx = {"base": cfg.base_url}
    ctx.update(ids)
    ctx.setdefault("orgId", ids.get("orgId") or ids.get("resource"))
    ctx.setdefault("userId", ids.get("userId") or ids.get("user"))
    ctx.setdefault("resource", ctx.get("orgId"))
    ctx.setdefault("user", ctx.get("userId"))
    return {k: v for k, v in ctx.items() if v is not None}


def _fmt(s, ctx):
    if not isinstance(s, str):
        return s
    for k, v in ctx.items():
        s = s.replace("{%s}" % k, str(v))
    return s


def _validate(v, results):
    rec = results.get(v.get("step")) if v else None
    if not v or not rec:
        return False
    if "status" in v and rec["status"] != v["status"]:
        return False
    if v.get("status_success") and rec["status"] not in SUCCESS:
        return False
    if "contains" in v and v["contains"] not in (rec.get("text") or ""):
        return False
    return True


def run_all(cfg, ev, **kw):
    specs = getattr(cfg, "declarative", []) or []
    if not specs:
        return []
    attacker = cfg.attacker()
    profiles = {p.name: p for p in cfg.profiles}
    profiles.setdefault("_anon", Profile("_anon", A.anon()))
    ctx = _ctx(cfg, attacker)
    session = requests.Session()
    findings = []

    for spec in specs:
        name = spec.get("name", "declarative")
        if (spec.get("requires") or {}).get("destructive") and not cfg.destructive:
            ev.log("decl:%s:skipped" % name, "-", cfg.base_url, "-", None, 0,
                   note="destructive requis")
            continue
        default_as = attacker.name if attacker else "_anon"
        results = {}
        for step in spec.get("steps", []):
            prof = profiles.get(step.get("as", default_as))
            if not prof:
                continue
            req = {"method": step.get("method", "GET").upper(),
                   "url": _fmt(step["url"], ctx), "headers": {},
                   "body": _fmt(step.get("body"), ctx)}
            results[step.get("id", "?")] = H.replay(
                session, cfg, req, prof, ev, "decl:%s:%s" % (name, step.get("id", "?")), **kw)

        ok = _validate(spec.get("validate") or {}, results)

        for rb in spec.get("rollback", []):  # rollback systematique
            prof = profiles.get(rb.get("as", default_as))
            if prof:
                H.replay(session, cfg, {"method": rb.get("method", "DELETE").upper(),
                                        "url": _fmt(rb["url"], ctx), "headers": {},
                                        "body": _fmt(rb.get("body"), ctx)},
                         prof, ev, "decl:%s:rollback" % name, **kw)

        if ok:
            findings.append({
                "type": spec.get("type", name),
                "severity": spec.get("severity", "high"),
                "cwe": spec.get("cwe", ""), "owasp_api": spec.get("owasp_api", ""),
                "title": spec.get("title") or ("Confirmation declarative: %s" % name),
                "evidence": {k: (r and {"status": r["status"]})
                             for k, r in results.items()},
            })
    return findings
