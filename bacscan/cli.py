# -*- coding: utf-8 -*-
"""bacscan - orchestrateur + CLI.

Pipeline : ingestion HAR -> moteur differentiel -> oracles -> sondes -> plugins
de confirmation -> findings + rapport. Usage autorise uniquement.
"""
import argparse
import sys

from . import config as C
from . import ingest, engine, report, oracles
from .probes import idor
from .plugins import role_escalation
from .http import Evidence

PROBES = {"idor": idor.run}
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
    return {"findings": findings, "matrix": matrix, "evidence": ev.events}


def main(argv=None):
    p = argparse.ArgumentParser(
        description="bacscan - scanner d'access control (BAC/IDOR). Usage autorise uniquement.")
    p.add_argument("--config", required=True, help="YAML d'engagement")
    p.add_argument("--har", required=True, help="Trafic capte (HAR)")
    p.add_argument("--insecure", action="store_true", help="Ne pas verifier le TLS")
    p.add_argument("--timeout", type=int, default=20)
    args = p.parse_args(argv)

    cfg = C.load_config(args.config)
    reqs = [r for r in ingest.from_har(args.har) if cfg.host_allowed(r["url"])]
    res = run(cfg, reqs, insecure=args.insecure, timeout=args.timeout)

    report.write_findings(res["findings"], cfg.findings_db)
    report.write_report(res["findings"], res["matrix"], cfg, cfg.report_md)

    print("[bacscan] %d requete(s) en scope, %d finding(s)"
          % (len(reqs), len(res["findings"])))
    for f in res["findings"]:
        print("  [%s] %s - %s" % (str(f.get("severity", "?")).upper(),
                                  f.get("type"), f.get("title", "")))
    return 1 if any(f.get("severity") in ("high", "critical")
                    for f in res["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
