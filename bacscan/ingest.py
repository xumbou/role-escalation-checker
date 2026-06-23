# -*- coding: utf-8 -*-
"""Ingestion -> requetes normalisees {method, url, headers, body, content_type}.

Deux sources :
  - HAR (export proxy/Burp/DevTools) : approche traffic-driven (capte la business logic).
  - OpenAPI 3 (JSON/YAML) : couverture exhaustive des endpoints declares.
"""
import json
import re


# --------------------------------------------------------------------------- #
# HAR
# --------------------------------------------------------------------------- #
def _headers_to_dict(headers):
    d = {}
    for h in headers or []:
        name = h.get("name", "")
        if name and not name.startswith(":"):  # ignore les pseudo-headers HTTP/2
            d[name] = h.get("value", "")
    return d


def from_har(path):
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
            "url": url, "headers": _headers_to_dict(req.get("headers")),
            "body": body, "content_type": ct,
        })
    return out


# --------------------------------------------------------------------------- #
# OpenAPI 3
# --------------------------------------------------------------------------- #
def _example_value(param):
    sch = param.get("schema") or {}
    if "example" in param:
        return param["example"]
    if "example" in sch:
        return sch["example"]
    if sch.get("enum"):
        return sch["enum"][0]
    return {"integer": 1, "number": 1, "boolean": True}.get(sch.get("type"), "1")


def _fill_path(path_tpl, params):
    res = path_tpl
    for p in params:
        if p.get("in") == "path":
            res = res.replace("{%s}" % p.get("name"), str(_example_value(p)))
    return re.sub(r"\{[^}]+\}", "1", res)  # tout placeholder restant -> 1


def _example_body(op):
    content = (op.get("requestBody") or {}).get("content") or {}
    js = content.get("application/json") or {}
    if "example" in js:
        return js["example"]
    sch = js.get("schema") or {}
    if "example" in sch:
        return sch["example"]
    props = sch.get("properties")
    if isinstance(props, dict):
        return {k: _example_value({"schema": v}) for k, v in props.items()}
    return None


def from_openapi(path, base_url=None):
    """OpenAPI 3 (JSON/YAML) -> requetes ; params de chemin remplaces par un exemple."""
    text = open(path, encoding="utf-8").read()
    try:
        spec = json.loads(text)
    except ValueError:
        import yaml
        spec = yaml.safe_load(text)
    servers = spec.get("servers") or []
    base = (base_url or (servers[0].get("url") if servers else "")).rstrip("/")
    out = []
    for path_tpl, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters", [])
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(op, dict):
                continue
            params = common + (op.get("parameters") or [])
            body = _example_body(op)
            out.append({
                "method": method.upper(),
                "url": base + _fill_path(path_tpl, params),
                "headers": {}, "body": body,
                "content_type": "application/json" if body else None,
            })
    return out
