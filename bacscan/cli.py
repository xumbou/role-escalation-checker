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
GROUPABLE = {"anonymous-access", "excessive-data-exposure"}


def _dedup(findings):
    """Supprime les findings strictement identiques (type, methode, url, champs)."""
    seen, out = set(), []
    for f in findings:
        req = f.get("request") or {}
        key = (f.get("type"), req.get("method"), req.get("url"),
               tuple(f.get("fields") or ()))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _group(findings):
    """Regroupe les types bruyants (broken-auth qui allume chaque endpoint) en 1 finding."""
    buckets, out = {}, []
    for f in findings:
        if f.get("type") in GROUPABLE:
            buckets.setdefault(f["type"], []).append(f)
        else:
            out.append(f)
    for t, fs in buckets.items():
        if len(fs) == 1:
            out.append(fs[0])
            continue
        urls = [(f.get("request") or {}).get("url") for f in fs]
        rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        agg = dict(fs[0])
        agg["severity"] = max((f.get("severity") for f in fs),
                              key=lambda s: rank.get(s, 0))  # garde la severite max du groupe
        agg["title"] = "%s sur %d endpoints (groupes): %s ..." % (t, len(fs), urls[0])
        agg["grouped_urls"] = urls
        agg["request"] = {"method": "*", "url": "%d endpoints" % len(fs)}
        out.append(agg)
    return out


def run(cfg, requests_list, **kw):
    """Execute le pipeline. Renvoie {findings, matrix, evidence}."""
    ev = Evidence()
    findings = []
    matrix = engine.build_matrix(cfg, requests_list, ev, **kw)
    findings += oracles.anonymous_access(matrix)
    findings += oracles.excessive_data(matrix, cfg)
    for name in cfg.probes:
        fn = PROBES.get(name)
        if fn:
            findings += fn(cfg, requests_list, ev, **kw)
    for name in cfg.impact_plugins:
        fn = PLUGINS.get(name)
        if fn:
            findings += fn(cfg, ev, **kw)
    findings += declarative.run_all(cfg, ev, **kw)  # plugins YAML declaratifs
    findings = _dedup(findings)                       # supprime les doublons stricts
    if cfg.group_findings:
        findings = _group(findings)                   # regroupe les types bruyants
    tri = triage.run(cfg, findings, ev, **kw)        # confirme / refute (avec raison loggee)
    return {"findings": findings, "matrix": matrix, "evidence": ev.events,
            "confirmed": tri["confirmed"], "false_positives": tri["false_positives"],
            "inconclusive": tri["inconclusive"], "triage_log": tri["log"]}


def cmd_scan(args):
    """Sous-commande `scan` (= comportement historique : HAR/OpenAPI/access-matrix)."""
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


def cmd_capture(args):
    """Sous-commande `capture` : proxy live -> HAR (scope-filtre, secrets en 0600)."""
    from . import capture
    try:
        capture.run_capture(args.allow_host, port=args.port,
                            har_out=args.har_out, flush_every=args.flush_every)
    except ImportError as exc:
        print(str(exc))
        return 3
    except ValueError as exc:
        print("[capture] %s" % exc)
        return 2
    return 0


def cmd_suggest(args):
    """Sous-commande `suggest` : HAR -> engagement.yaml genere (AUCUNE requete)."""
    from . import suggest
    det = suggest.analyze(args.har)
    if not det.get("host"):
        print("[suggest] aucun host detecte dans le HAR (HAR vide ?) -- capture du trafic d'abord")
        return 2
    print(suggest.format_recap(det))
    try:
        suggest.write_engagement(det, args.out, engagement=args.engagement)
    except Exception as exc:  # noqa: BLE001  -- ConfigError ou IO
        print("[suggest] ECHEC : le YAML genere n'est pas valide : %r" % exc)
        return 2
    print("[suggest] engagement ecrit (0600, contient des secrets) -> %s" % args.out)
    print("[suggest] valide par config.load_config. Relis-le avant tout scan.")
    return 0


def cmd_watch(args):
    """Sous-commande `watch` : surveille le HAR, relance le pipeline en SAFE."""
    from . import watch as W
    W.watch(args.config, args.har, interval=args.interval,
            auto_suggest=args.auto_suggest, out_suggest=args.out_suggest)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="bacscan",
        description="bacscan - scanner d'access control (BAC/IDOR). Usage autorise uniquement.")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="Scanner un HAR/OpenAPI/access-matrix (defaut)")
    sp.add_argument("--config", required=True, help="YAML d'engagement")
    sp.add_argument("--har", help="Trafic capte (HAR)")
    sp.add_argument("--openapi", help="Spec OpenAPI 3 (JSON/YAML)")
    sp.add_argument("--access-matrix", dest="access_matrix",
                    help="access_matrix.json (analyse statique) -> candidats prioritaires")
    sp.add_argument("--insecure", action="store_true", help="Ne pas verifier le TLS")
    sp.add_argument("--timeout", type=int, default=20)
    sp.set_defaults(func=cmd_scan)

    cp = sub.add_parser("capture", help="Capturer le trafic live via proxy -> HAR (extra mitmproxy)")
    cp.add_argument("--allow-host", dest="allow_host", action="append", required=True,
                    help="Host autorise (repetable) ; tout autre host est ignore")
    cp.add_argument("--port", type=int, default=8080, help="Port d'ecoute du proxy")
    cp.add_argument("--har-out", dest="har_out", default="traffic.har",
                    help="Fichier HAR de sortie (cree en 0600)")
    cp.add_argument("--flush-every", dest="flush_every", type=int, default=1,
                    help="Reecrire le HAR toutes les N entrees")
    cp.set_defaults(func=cmd_capture)

    gp = sub.add_parser("suggest", help="Auto-detecter -> engagement.yaml (aucune requete)")
    gp.add_argument("--har", required=True, help="HAR a analyser")
    gp.add_argument("--out", default="engagement.suggested.yaml",
                    help="YAML genere (cree en 0600, contient des secrets)")
    gp.add_argument("--engagement", default="assisted-engagement",
                    help="Nom de l'engagement")
    gp.set_defaults(func=cmd_suggest)

    wp = sub.add_parser("watch", help="Surveiller le HAR et relancer le pipeline en SAFE")
    wp.add_argument("--config", required=True, help="YAML d'engagement")
    wp.add_argument("--har", required=True, help="HAR a surveiller")
    wp.add_argument("--interval", type=int, default=5, help="Intervalle de polling (s)")
    wp.add_argument("--auto-suggest", dest="auto_suggest", action="store_true",
                    help="Regenerer aussi les suggestions sur nouveaux endpoints")
    wp.add_argument("--out-suggest", dest="out_suggest", default="engagement.suggested.yaml",
                    help="Cible des suggestions auto (avec --auto-suggest)")
    wp.set_defaults(func=cmd_watch)
    return p


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    # Retro-compat : aucun sous-commande mais --config present -> agir comme `scan`.
    known = {"scan", "capture", "suggest", "watch", "-h", "--help"}
    if argv and argv[0] not in known and any(a in ("--config",) for a in argv):
        argv = ["scan"] + list(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
