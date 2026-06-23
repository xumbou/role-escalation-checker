# -*- coding: utf-8 -*-
"""Triage des findings : confirme l'exploitabilite, ou explique POURQUOI c'est un
faux positif -- et journalise ce pourquoi.

Double objectif demande :
  1. comprendre un faux positif (raison explicite) ;
  2. detecter quand l'OUTIL lui-meme sur-detecte (oracle trop faible).

Verdicts   : confirmed | false_positive | inconclusive
Categories : benign          -> vrai FP "metier" (ressource publique, donnee partagee)
             tool_limitation -> signal d'amelioration de l'oracle/sonde (2xx vide, non verifiable)
             impact / access / info -> finding tenu pour reel

Heuristiques de refutation (non destructives) :
  - ressource accessible SANS authentification -> publique, pas un bypass d'autorisation ;
  - 2xx mais corps vide -> no-op probable, l'oracle a renforcer ;
  - BOPLA : champ injecte reflete mais persistance non confirmee a la relecture.
"""
import logging

import requests

from . import http as H
from . import auth as A
from .config import Profile

SUCCESS = (200, 201, 202, 204)
GET_ACCESS = {"idor", "idor-dynamic", "idor-sequential", "bfla"}


def _logger(path):
    lg = logging.getLogger("bacscan.triage")
    lg.setLevel(logging.INFO)
    lg.handlers = []  # repart propre a chaque run (evite les doublons)
    if path:
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        lg.addHandler(fh)
    return lg


def _url(f):
    return (f.get("request") or {}).get("url", "?")


def run(cfg, findings, ev, **kw):
    lg = _logger(getattr(cfg, "triage_log", None))
    session = requests.Session()
    anon = Profile("_anon", A.anon())
    confirmed, fps, inconc, log = [], [], [], []

    for f in findings:
        verdict, reason, category, extra = _assess(cfg, f, session, anon, ev, **kw)
        f["verdict"] = verdict
        f["triage"] = {"reason": reason, "category": category}
        f["triage"].update(extra)
        log.append({"verdict": verdict, "type": f.get("type"), "url": _url(f),
                    "category": category, "reason": reason})
        if verdict == "confirmed":
            confirmed.append(f)
        elif verdict == "false_positive":
            fps.append(f)
            lg.warning("FALSE_POSITIVE type=%s url=%s category=%s reason=%s",
                       f.get("type"), _url(f), category, reason)
        else:
            inconc.append(f)
            lg.info("INCONCLUSIVE type=%s url=%s category=%s reason=%s",
                    f.get("type"), _url(f), category, reason)

    if fps or inconc:
        lg.info("TRIAGE summary: %d confirmed / %d false_positive / %d inconclusive",
                len(confirmed), len(fps), len(inconc))
    return {"confirmed": confirmed, "false_positives": fps,
            "inconclusive": inconc, "log": log}


def _assess(cfg, f, session, anon, ev, **kw):
    t = f.get("type", "")
    if f.get("confirmed_by") == "plugin":
        return "confirmed", "impact prouve par un plugin de confirmation", "impact", {}
    if t in ("privilege-escalation", "anonymous-access"):
        return "confirmed", "impact/acces materialise", "impact", {}
    if t == "graphql-introspection":
        return "confirmed", "introspection repond (information disclosure)", "info", {}
    if t == "existence-leakage":
        return "confirmed", "divergence 403/404 confirmee", "info", {}
    if t == "graphql-idor":
        return "confirmed", "data non-nul sans erreur d'autorisation (oracle GraphQL)", "access", {}
    if t == "bfla-asymmetry":
        return "confirmed", "asymetrie de verbes detectee (oracle)", "access", {}
    if t == "bopla":
        return _assess_bopla(cfg, f, session, ev, **kw)
    if t in GET_ACCESS:
        return _assess_get_access(cfg, f, session, anon, ev, **kw)
    return "inconclusive", "type non couvert par le triage", "tool_limitation", {}


def _assess_get_access(cfg, f, session, anon, ev, **kw):
    req = f.get("request") or {}
    if req.get("method", "GET") != "GET":
        return "confirmed", "acces authentifie (verbe non rejouable a l'anon)", "access", {}
    # 1) ressource publique ? accessible SANS authentification -> pas un bypass d'autorisation
    r = H.replay(session, cfg, {"method": "GET", "url": req["url"], "headers": {},
                                "body": None}, anon, ev, "triage:anon:" + req["url"], **kw)
    if r and r["status"] in SUCCESS:
        return ("false_positive",
                "ressource accessible SANS authentification -> publique, pas un bypass d'autorisation",
                "benign", {"anon_status": r["status"]})
    # 2) corps vide -> 2xx peu significatif (signal d'oracle faible)
    ev_rec = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    if ev_rec.get("length") == 0:
        return ("inconclusive",
                "2xx mais corps vide (no-op probable) -> oracle a renforcer",
                "tool_limitation", {"length": 0})
    return ("confirmed",
            "2xx authentifie, refuse a l'anon (%s), corps non vide"
            % (r["status"] if r else "n/a"),
            "access", {"anon_status": r["status"] if r else None})


def _assess_bopla(cfg, f, session, ev, **kw):
    conf = cfg.plugin_conf.get("role_escalation") or {}
    attacker = cfg.attacker()
    list_tpl = conf.get("list_path")
    if not (list_tpl and attacker):
        return ("inconclusive",
                "champ injecte reflete mais effet non verifiable automatiquement (reflet seul)",
                "tool_limitation", {})
    resource = attacker.ids.get("orgId") or attacker.ids.get("resource")
    url = cfg.base_url + list_tpl.replace("{resource}", str(resource)).replace("{user}", "")
    r = H.replay(session, cfg, {"method": "GET", "url": url, "headers": {}, "body": None},
                 attacker, ev, "triage:bopla-verify", **kw)
    inj = cfg.bopla.get("inject_fields") or {"role": "ADMINISTRATOR"}
    needle = str(list(inj.values())[0])
    if r and r["status"] in SUCCESS and needle in (r.get("text") or ""):
        return "confirmed", "champ injecte persiste cote serveur (effet materialise)", "impact", {}
    return ("inconclusive",
            "champ reflete mais persistance non confirmee a la relecture",
            "tool_limitation", {})
