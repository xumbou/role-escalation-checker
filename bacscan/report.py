# -*- coding: utf-8 -*-
"""Sortie : findings JSON (ingestible par un findings_db) + matrice/rapport Markdown."""
import json
import os


def _ensure_dir(path):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)


def write_findings(findings, path):
    if not path:
        return
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"findings": findings}, fh, indent=2, ensure_ascii=False)


def write_audit(events, path):
    """Journal d'audit : toutes les requetes envoyees (horodatees) = tracabilite legale."""
    if not path:
        return
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"events": events}, fh, indent=2, ensure_ascii=False)


def write_report(findings, matrix, cfg, path):
    if not path:
        return
    _ensure_dir(path)
    profiles = [p.name for p in cfg.profiles]
    conf = [f for f in findings if f.get("verdict") == "confirmed"]
    triaged = [f for f in findings if f.get("verdict") in ("false_positive", "inconclusive")]
    lines = ["# Rapport BAC - %s" % cfg.engagement, ""]
    lines.append("## Findings confirmes (%d)" % len(conf))
    lines.append("")
    lines.append("| Severite | Type | CWE | OWASP-API | Titre |")
    lines.append("|---|---|---|---|---|")
    for f in conf:
        lines.append("| %s | %s | %s | %s | %s |" % (
            f.get("severity"), f.get("type"), f.get("cwe"),
            f.get("owasp_api", ""), str(f.get("title", "")).replace("|", "/")))
    if triaged:
        lines += ["", "## Triage : faux positifs & inconclusive (%d)" % len(triaged), ""]
        lines.append("| Verdict | Categorie | Type | URL | Raison |")
        lines.append("|---|---|---|---|---|")
        for f in triaged:
            tr = f.get("triage", {})
            lines.append("| %s | %s | %s | %s | %s |" % (
                f.get("verdict"), tr.get("category"), f.get("type"),
                str((f.get("request") or {}).get("url", "")).replace("|", "/"),
                str(tr.get("reason", "")).replace("|", "/")))
    lines += ["", "## Matrice d'acces", ""]
    lines.append("| Requete | " + " | ".join(profiles) + " |")
    lines.append("|---" * (len(profiles) + 1) + "|")
    for row in matrix:
        req = row["request"]
        cells = []
        for pn in profiles:
            rec = row["by_profile"].get(pn)
            cells.append(str(rec["status"]) if rec else "-")
        label = ("%s %s" % (req["method"], req["url"])).replace("|", "/")
        lines.append("| %s | %s |" % (label, " | ".join(cells)))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
