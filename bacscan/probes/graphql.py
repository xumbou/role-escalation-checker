# -*- coding: utf-8 -*-
"""Sonde GraphQL : introspection activee + IDOR via variables.

GraphQL renvoie souvent HTTP 200 meme sur erreur d'autorisation (erreurs dans le
tableau 'errors'). L'oracle de succes verifie : 200 + 'data' non-nul + pas d'erreur
d'autorisation explicite.
"""
import copy
import json

import requests

from .. import http as H
from .. import auth as A
from ..config import Profile

INTROSPECTION = {"query": "{__schema{types{name}}}"}
_AUTHZ_WORDS = ("permission", "unauthor", "forbidden", "not allowed", "denied")


def _is_gql(req):
    return req["url"].rstrip("/").endswith("/graphql") or \
        "graphql" in (req.get("content_type") or "").lower()


def _gql_success(rec):
    if not rec or rec["status"] != 200 or not rec.get("text"):
        return False
    try:
        body = json.loads(rec["text"])
    except ValueError:
        return False
    if not isinstance(body, dict) or not body.get("data"):
        return False
    blob = json.dumps(body.get("errors") or []).lower()
    return not any(w in blob for w in _AUTHZ_WORDS)


def _body_obj(req):
    body = req.get("body")
    try:
        if isinstance(body, str):
            return json.loads(body)
        return body if isinstance(body, dict) else None
    except ValueError:
        return None


def run(cfg, requests_list, ev, **kw):
    attacker = cfg.attacker()
    if not attacker:
        return []
    s = requests.Session()
    s.headers.update({"User-Agent": "bacscan-graphql"})
    findings = []
    endpoints = sorted({r["url"] for r in requests_list if _is_gql(r)})

    # 1) introspection activee ?
    for url in endpoints:
        rec = H.replay(s, cfg, {"method": "POST", "url": url, "headers": {},
                                "body": INTROSPECTION,
                                "content_type": "application/json"},
                       attacker, ev, "gql:introspection:%s" % url, **kw)
        if rec and rec["status"] == 200 and "__schema" in (rec.get("text") or ""):
            findings.append({
                "type": "graphql-introspection", "severity": "medium",
                "cwe": "CWE-200", "owasp_api": "API8:2023",
                "title": "GraphQL introspection activee sur %s" % url,
                "request": {"method": "POST", "url": url}, "evidence": rec})

    # 2) IDOR via substitution dans les variables
    for req in requests_list:
        if not _is_gql(req):
            continue
        obj = _body_obj(req)
        if not isinstance(obj, dict) or "variables" not in obj:
            continue
        variables = obj.get("variables") or {}
        for key, my_val in attacker.ids.items():
            for victim in [p for p in cfg.profiles if p is not attacker and p.ids]:
                v_val = victim.ids.get(key)
                if not v_val:
                    continue
                newvars = {k: (str(v_val) if str(v) == str(my_val) else v)
                           for k, v in variables.items()}
                if newvars == variables:
                    continue
                tampered = copy.deepcopy(obj)
                tampered["variables"] = newvars
                rec = H.replay(s, cfg, req, attacker, ev,
                               "gql:idor:%s:%s->%s" % (key, my_val, v_val),
                               body_override=tampered, **kw)
                if _gql_success(rec):
                    findings.append({
                        "type": "graphql-idor", "severity": "high",
                        "cwe": "CWE-639", "owasp_api": "API1:2023",
                        "title": "GraphQL IDOR via variables (%s %s->%s) sur %s"
                                 % (key, my_val, v_val, req["url"]),
                        "request": {"method": "POST", "url": req["url"]},
                        "attacker": attacker.name, "victim": victim.name,
                        "evidence": rec})

    # 3) BFLA : une mutation executable SANS authentification (gate destructive)
    if cfg.destructive:
        anon = Profile("_anon", A.anon())
        seen = set()
        for req in requests_list:
            if not _is_gql(req):
                continue
            obj = _body_obj(req)
            query = (obj or {}).get("query", "") if isinstance(obj, dict) else ""
            if "mutation" not in query.lower() or req["url"] in seen:
                continue
            seen.add(req["url"])
            rec = H.replay(s, cfg, req, anon, ev, "gql:bfla:%s" % req["url"], **kw)
            if _gql_success(rec):
                findings.append({
                    "type": "graphql-bfla", "severity": "high",
                    "cwe": "CWE-285", "owasp_api": "API5:2023",
                    "title": "Mutation GraphQL executable sans authentification sur %s" % req["url"],
                    "request": {"method": "POST", "url": req["url"]},
                    "evidence": rec})
    return findings
