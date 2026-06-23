# -*- coding: utf-8 -*-
"""Watch : surveille un HAR live et relance le pipeline en SAFE a chaque changement.

A chaque modification du HAR (mtime + taille, debounce `interval`), re-parse, ne
garde que les NOUVELLES requetes (clef (method,url) deja vues), et relance
cli.run() en mode SAFE -- `destructive` est FORCE a False quoi que dise le YAML.
Aucune mutation automatique. Met a jour findings_db / report_md ; affiche un
resume incremental (nouveaux confirmes). Ctrl-C propre.

Usage autorise uniquement (lab / CTF / engagement signe).
"""
import os
import sys
import time

from . import config as C
from . import ingest, cli, report
from .redact import redact


def _safe_print(msg):
    msg = redact(msg)
    try:
        sys.stdout.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(msg.encode("ascii", "replace").decode("ascii") + "\n")
    sys.stdout.flush()


def _stat(path):
    """(mtime, size) du HAR, ou None s'il n'existe pas encore."""
    try:
        st = os.stat(path)
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


def _force_safe(cfg):
    """Garde-fou DUR : impose le mode non destructif au Config charge."""
    cfg.destructive = False


def _new_in_scope(cfg, har_path, seen):
    """Requetes en scope, dedupliquees, jamais vues -> ajoute a `seen`."""
    fresh = []
    for r in ingest.from_har(har_path):
        key = (r["method"], r["url"])
        if key in seen or not cfg.host_allowed(r["url"]):
            continue
        seen.add(key)
        fresh.append(r)
    return fresh


def watch(config_path, har_path, interval=5, auto_suggest=False, out_suggest=None,
          run_fn=None, max_iterations=None):
    """Boucle de surveillance. Renvoie le nombre d'iterations de scan effectuees.

    `run_fn` : injectable pour les tests (defaut = cli.run). `max_iterations` :
    borne la boucle (None = infini jusqu'a Ctrl-C).
    """
    run_fn = run_fn or cli.run
    cfg = C.load_config(config_path)
    _force_safe(cfg)  # SAFE non negociable

    _safe_print("[watch] config = %s (SAFE force : destructive=False)" % config_path)
    _safe_print("[watch] surveillance de %s toutes les %ss (Ctrl-C pour arreter)"
                % (har_path, interval))
    _safe_print("[watch] scope : %s" % ", ".join(sorted(cfg.allow_hosts)))

    seen = set()
    last = None
    iterations = 0

    try:
        while True:
            cur = _stat(har_path)
            changed = cur is not None and cur != last
            if changed:
                # debounce : attendre que le fichier se stabilise
                time.sleep(min(interval, 1))
                stable = _stat(har_path)
                if stable != cur:
                    last = stable
                    continue
                last = cur
                fresh = _new_in_scope(cfg, har_path, seen)
                if fresh:
                    iterations += 1
                    res = run_fn(cfg, fresh)
                    _flush_outputs(cfg, res)
                    conf = res.get("confirmed", [])
                    _safe_print("[watch] +%d nouvelle(s) requete(s) -> %d finding(s), %d confirme(s)"
                                % (len(fresh), len(res.get("findings", [])), len(conf)))
                    for f in conf:
                        _safe_print("  [%s] %s - %s"
                                    % (str(f.get("severity", "?")).upper(),
                                       f.get("type"), f.get("title", "")))
                    if auto_suggest and out_suggest:
                        _maybe_suggest(har_path, out_suggest)
                if max_iterations is not None and iterations >= max_iterations:
                    break
            if max_iterations is not None and iterations >= max_iterations:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        _safe_print("[watch] arret.")
    return iterations


def _flush_outputs(cfg, res):
    """Reecrit findings_db / report_md / audit_log si definis (idempotent)."""
    findings = res.get("findings", [])
    if cfg.findings_db:
        report.write_findings(findings, cfg.findings_db)
    if cfg.report_md:
        report.write_report(findings, res.get("matrix", []), cfg, cfg.report_md)
    if cfg.audit_log and res.get("evidence") is not None:
        report.write_audit(res["evidence"], cfg.audit_log)


def _maybe_suggest(har_path, out_suggest):
    """Regenere les suggestions (read-only) sur nouveaux endpoints/roles."""
    try:
        from . import suggest as S
        det = S.analyze(har_path)
        S.write_engagement(det, out_suggest)
        _safe_print("[watch] suggestions regenerees -> %s" % out_suggest)
    except Exception as exc:  # noqa: BLE001
        _safe_print("[watch] suggest auto ignore : %r" % exc)
