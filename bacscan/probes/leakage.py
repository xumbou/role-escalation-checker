# -*- coding: utf-8 -*-
"""Oracle 'existence leakage' (arXiv) : un endpoint qui renvoie 403 sur une ressource
EXISTANTE mais 404 sur une ressource ABSENTE revele l'existence (aide a l'enumeration,
prepare une exploitation BOLA). Non destructif (GET uniquement)."""
import requests

from .. import http as H

BOGUS = "zz-nonexistent-000"


def _swap_last_segment(url, new):
    base, sep, _ = url.rstrip("/").rpartition("/")
    return base + "/" + new if sep else url


def run(cfg, requests_list, ev, **kw):
    attacker = cfg.attacker()
    if not attacker:
        return []
    s = requests.Session()
    s.headers.update({"User-Agent": "bacscan-leak"})
    findings, seen = [], set()
    for req in requests_list:
        if req["method"] != "GET":
            continue
        url = req["url"]
        if url in seen:
            continue
        seen.add(url)
        bogus_url = _swap_last_segment(url, BOGUS)
        if bogus_url == url:
            continue
        real = H.replay(s, cfg, req, attacker, ev, "leak:real:%s" % url, **kw)
        bog = H.replay(s, cfg, {"method": "GET", "url": bogus_url, "headers": {},
                               "body": None}, attacker, ev,
                       "leak:bogus:%s" % bogus_url, **kw)
        if real and bog and real["status"] == 403 and bog["status"] == 404:
            findings.append({
                "type": "existence-leakage", "severity": "low",
                "cwe": "CWE-204", "owasp_api": "API1:2023",
                "title": "Existence leakage sur %s: 403 (existe) vs 404 (absent)" % url,
                "request": {"method": "GET", "url": url},
                "attacker": attacker.name,
                "evidence": {"real": real, "bogus": bog},
            })
    return findings
