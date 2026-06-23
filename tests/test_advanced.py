# -*- coding: utf-8 -*-
"""Verification empirique des features 'vrai outil de pentest' :
auth pluggable (OAuth refresh + CSRF), IDOR dynamique/sequentiel, plugin declaratif, GraphQL."""
import json
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan.config import Config
from bacscan import cli, http as H
from bacscan.http import Evidence
import mock_server


def _cfg(profiles, base, **extra):
    d = {"engagement": "adv", "base_url": base,
         "scope": {"allow_hosts": ["127.0.0.1"]},
         "auth": {"header": "Authorization", "prefix": "Bearer "},
         "profiles": profiles, "safety": {"destructive": True, "rollback": "auto"}}
    d.update(extra)
    return Config(d)


def test_oauth_refresh(base):
    cfg = _cfg([{"name": "low", "ids": {"userId": "u-1001"}, "auth": {
        "type": "oauth", "token": "expired-1",
        "refresh": {"url": base + "/oauth/token", "refresh_token": "rt-1",
                    "token_field": "access_token"}}}], base)
    rec = H.replay(requests.Session(), cfg, {"method": "GET",
                   "url": base + "/users/u-1001", "headers": {}, "body": None},
                   cfg.profile("low"), Evidence(), "t")
    assert rec and rec["status"] == 200, "OAuth refresh KO: %s" % (rec and rec["status"])
    print("[OK] OAuth refresh : token expire -> 401 -> refresh -> 200")


def test_csrf(base):
    cfg = _cfg([{"name": "low", "auth": {"type": "bearer", "token": "low-token"},
                 "csrf": {"fetch_url": base + "/csrf-token", "cookie": "XSRF-TOKEN",
                          "header": "X-CSRF-Token", "methods": ["POST"]}}], base)
    rec = H.replay(requests.Session(), cfg, {"method": "POST",
                   "url": base + "/csrf-protected", "headers": {}, "body": {}},
                   cfg.profile("low"), Evidence(), "t")
    assert rec and rec["status"] == 200, "CSRF KO: %s" % (rec and rec["status"])
    print("[OK] CSRF : token recupere du cookie et injecte -> 200")


def test_dynamic_idor(base):
    cfg = _cfg([{"name": "anon", "token": None},
                {"name": "low", "token": "low-token", "ids": {"userId": "u-1001"}},
                {"name": "victim", "token": "victim-token", "ids": {"userId": "u-2002"}}],
               base, probes=["idor_dynamic"])
    reqs = [{"method": "GET", "url": base + "/documents", "headers": {}, "body": None},
            {"method": "GET", "url": base + "/invoices/100", "headers": {}, "body": None}]
    types = {f["type"] for f in cli.run(cfg, reqs)["findings"]}
    assert "idor-dynamic" in types, "harvest/chainage KO"
    assert "idor-sequential" in types, "enumeration sequentielle KO"
    print("[OK] IDOR dynamique (chainage) + IDOR sequentiel")


def test_declarative(base):
    spec = {"name": "role-escalation", "requires": {"destructive": True},
            "steps": [
                {"id": "promote", "method": "POST",
                 "url": "{base}/orgs/{orgId}/administrators/{userId}", "as": "low"},
                {"id": "check", "method": "GET",
                 "url": "{base}/orgs/{orgId}/members", "as": "low"}],
            "validate": {"step": "check", "status_success": True, "contains": "ADMINISTRATOR"},
            "rollback": [{"method": "DELETE",
                          "url": "{base}/orgs/{orgId}/members/{userId}", "as": "low"}],
            "severity": "critical", "cwe": "CWE-269", "owasp_api": "API5:2023"}
    cfg = _cfg([{"name": "low", "token": "low-token",
                 "ids": {"orgId": "o-50", "userId": "u-1001"}}],
               base, declarative_plugins=[spec])
    types = {f["type"] for f in cli.run(cfg, [])["findings"]}
    assert "role-escalation" in types, "plugin declaratif KO"
    print("[OK] Plugin de confirmation declaratif (YAML, sans code)")


def test_graphql(base):
    cfg = _cfg([{"name": "anon", "token": None},
                {"name": "low", "token": "low-token", "ids": {"userId": "u-1001"}},
                {"name": "victim", "token": "victim-token", "ids": {"userId": "u-2002"}}],
               base, probes=["graphql"])
    reqs = [{"method": "POST", "url": base + "/graphql",
             "content_type": "application/json",
             "body": json.dumps({"query": "query($id:ID!){user(id:$id){email}}",
                                 "variables": {"id": "u-1001"}})}]
    types = {f["type"] for f in cli.run(cfg, reqs)["findings"]}
    assert "graphql-introspection" in types, "introspection KO"
    assert "graphql-idor" in types, "GraphQL IDOR via variables KO"
    print("[OK] GraphQL : introspection + IDOR via variables")


def main():
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        test_oauth_refresh(base)
        test_csrf(base)
        test_dynamic_idor(base)
        test_declarative(base)
        test_graphql(base)
    finally:
        httpd.shutdown()
    print("\nOK: auth pluggable + IDOR dynamique + plugins declaratifs + GraphQL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
