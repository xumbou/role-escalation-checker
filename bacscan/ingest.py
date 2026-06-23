# -*- coding: utf-8 -*-
"""Ingestion : HAR (export proxy/Burp/DevTools) -> requetes normalisees.

Approche traffic-driven (cf. Akto) : partir du trafic reel capte plutot que d'un
simple OpenAPI -> on capte la business logic et on reduit les faux positifs.
"""
import json


def _headers_to_dict(headers):
    d = {}
    for h in headers or []:
        name = h.get("name", "")
        if name and not name.startswith(":"):  # ignore les pseudo-headers HTTP/2
            d[name] = h.get("value", "")
    return d


def from_har(path):
    """Renvoie une liste de requetes {method, url, headers, body, content_type}."""
    with open(path, encoding="utf-8") as fh:
        har = json.load(fh)
    out = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url")
        if not url:
            continue
        body, ct = None, None
        pd = req.get("postData")
        if pd:
            ct = pd.get("mimeType")
            body = pd.get("text")
        out.append({
            "method": req.get("method", "GET").upper(),
            "url": url,
            "headers": _headers_to_dict(req.get("headers")),
            "body": body,
            "content_type": ct,
        })
    return out
