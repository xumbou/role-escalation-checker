# -*- coding: utf-8 -*-
"""bacscan - orchestrateur + CLI.

Pipeline : ingestion (HAR/OpenAPI) [+ candidats statiques] -> moteur differentiel
-> oracles -> sondes (IDOR/BFLA/BOPLA/leakage) -> plugins de confirmation
-> findings + rapport. Usage autorise uniquement.
"""
import argparse
import sys

from . import config as C
from . import ingest, engine, report, oracles, static_link, triage
from .probes import idor, bfla, bopla, leakage, idor_dynamic, graphql
from .plugins import role_escalation, declarative
from .http import Evidence

PROBES = {"idor": idor.run, "bfla": bfla.run, "bopla": bopla.run,
          "leakage": leakage.run, "idor_dynamic": idor_dynamic.run,
          "graphql": graphql.run}
PLUGINS = {"role_escalation": role_escalation.run}


def run(cfg, requests_list, **kw):
    """Execute le pipeline. Renvoie {findings, matrix, evidence}."""
    ev = Evidence()
    findings = []
    matrix = engine.build_matrix(cfg, requests_list, ev, **kw)
    findings += oracles.anonymous_access(matrix)
    for name in cfg.probes:
        fn = PROBES.get(name)
        if fn:
            findings += fn(cfg, requests_list, ev, **kw)
    for name in cfg.impact_plugins:
        fn = PLUGINS.get(name)
        if fn:
            findings += fn(cfg, ev, **kw)
    findings += declarative.run_all(cfg, ev, **kw)  # plugins YAML declaratifs
    tri = triage.run(cfg, findings, ev, **kw)        # confirme / refute (avec raison loggee)
    return {"findings": findings, "matrix": matrix, "evidence": ev.events,
            "confirmed": tri["confirmed"], "false_positives": tri["false_positives"],
            "inconclusive": tri["inconclusive"], "triage_log": tri["log"]}


def main(argv=None):
    p = argparse.ArgumentParser(
        description="bacscan - scanner d'access control (BAC/IDOR). Usage autorise uniquement.")
    p.add_argument("--config", required=True, help="YAML d'engagement")
    p.add_argument("--har", help="Trafic capte (HAR)")
    p.add_argument("--openapi", help="Spec OpenAPI 3 (JSON/YAML)")
    p.add_argument("--access-matrix", dest="access_matrix",
                   help="access_matrix.json (analyse statique) -> candidats prioritaires")
    p.add_argument("--insecure", action="store_true", help="Ne pas verifier le TLS")
    p.add_argument("--timeout", type=int, default=20)
    args = p.parse_args(argv)

    cfg = C.load_config(args.config)
    sourced = []
    if args.har:
        sourced += ingest.from_har(args.har)
    if args.openapi:
        sourced += ingest.from_openapi(args.openapi, base_url=cfg.base_url)
    if args.access_matrix:
        cand = static_link.load_candidates(args.access_matrix, cfg.base_url)
        print("[bacscan] %d candidat(s) issus de l'analyse statique" % len(cand))
        sourced += cand

    # dedup (method, url) + filtre de scope
    seen, reqs = set(), []
    for r in sourced:
        k = (r["method"], r["url"])
        if k in seen or not cfg.host_allowed(r["url"]):
            continue
        seen.add(k)
        reqs.append(r)
    if not reqs:
        print("[bacscan] aucune requete en scope (fournir --har et/ou --openapi)")
        return 2

    res = run(cfg, reqs, insecure=args.insecure, timeout=args.timeout)
    report.write_findings(res["findings"], cfg.findings_db)
    report.write_report(res["findings"], res["matrix"], cfg, cfg.report_md)
    report.write_audit(res["evidence"], cfg.audit_log)

    conf, fps, inc = res["confirmed"], res["false_positives"], res["inconclusive"]
    print("[bacscan] %d requete(s), %d finding(s) -> %d confirme(s), %d faux positif(s), %d inconclusive"
          % (len(reqs), len(res["findings"]), len(conf), len(fps), len(inc)))
    for f in conf:
        print("  [%s] %s - %s" % (str(f.get("severity", "?")).upper(),
                                  f.get("type"), f.get("title", "")))
    if fps or inc:
        print("  triage : %d filtre(s) -> %s"
              % (len(fps) + len(inc), cfg.triage_log or "(definir output.triage_log pour journaliser)"))
    return 1 if any(f.get("severity") in ("high", "critical") for f in conf) else 0


if __name__ == "__main__":
    sys.exit(main())
