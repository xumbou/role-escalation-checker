#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batterie de checks locaux pour bacscan.

  1. compile        : tous les .py compilent
  2. imports        : tous les modules s'importent
  3. e2e            : detection des 6 classes (test_e2e)
  4. advanced       : auth/dynamic/declaratif/graphql (test_advanced)
  5. non-destructif : aucune mutation d'etat sans safety.destructive
  6. smoke-cli      : python -m bacscan.cli ecrit findings.json + report.md
  7. scope-guard    : un hote hors allow_hosts est refuse
"""
import copy
import glob
import importlib
import json
import os
import py_compile
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

RESULTS = []


def run(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ""))
        print("[PASS] %s" % name)
    except Exception as exc:  # noqa: BLE001
        RESULTS.append((name, False, repr(exc)))
        print("[FAIL] %s -> %r" % (name, exc))


# --------------------------------------------------------------------------- #
def c_compile():
    files = (glob.glob(os.path.join(ROOT, "bacscan", "**", "*.py"), recursive=True)
             + glob.glob(os.path.join(ROOT, "tools", "*.py"))
             + glob.glob(os.path.join(HERE, "*.py")))
    assert files, "aucun fichier trouve"
    for f in files:
        py_compile.compile(f, doraise=True)


def c_imports():
    mods = ["bacscan", "bacscan.config", "bacscan.auth", "bacscan.http", "bacscan.engine",
            "bacscan.ingest", "bacscan.oracles", "bacscan.harvest", "bacscan.report",
            "bacscan.static_link", "bacscan.cli", "bacscan.probes.idor",
            "bacscan.probes.bfla", "bacscan.probes.bopla", "bacscan.probes.leakage",
            "bacscan.probes.idor_dynamic", "bacscan.probes.graphql",
            "bacscan.plugins.role_escalation", "bacscan.plugins.declarative"]
    for m in mods:
        importlib.import_module(m)


def c_e2e():
    import test_e2e
    assert test_e2e.main() == 0


def c_advanced():
    import test_advanced
    assert test_advanced.main() == 0


def _full_cfg(base, destructive):
    return {
        "engagement": "checks", "base_url": base,
        "scope": {"allow_hosts": ["127.0.0.1"]},
        "auth": {"header": "Authorization", "prefix": "Bearer "},
        "profiles": [
            {"name": "anon", "token": None},
            {"name": "low", "token": "low-token", "ids": {"userId": "u-1001", "orgId": "o-50"}},
            {"name": "victim", "token": "victim-token", "ids": {"userId": "u-2002", "orgId": "o-77"}},
        ],
        "safety": {"destructive": destructive, "rollback": "auto"},
        "probes": ["idor", "idor_dynamic", "bfla", "bopla", "leakage"],
        "impact_plugins": ["role_escalation"],
        "declarative_plugins": [{
            "name": "role-escalation", "requires": {"destructive": True},
            "steps": [{"id": "p", "method": "POST",
                       "url": "{base}/orgs/{orgId}/administrators/{userId}", "as": "low"}],
            "validate": {"step": "p", "status_success": True}}],
        "role_escalation": {"list_path": "/orgs/{resource}/members",
                            "promote_path": "/orgs/{resource}/administrators/{user}",
                            "rollback_path": "/orgs/{resource}/members/{user}"},
    }


def _har(base):
    auth = [{"name": "Authorization", "value": "Bearer captured"}]
    return {"log": {"entries": [
        {"request": {"method": "GET", "url": base + "/orgs/o-50/members", "headers": auth}},
        {"request": {"method": "GET", "url": base + "/orgs/o-50/settings", "headers": auth}},
        {"request": {"method": "GET", "url": base + "/secrets/s-1", "headers": auth}},
        {"request": {"method": "GET", "url": base + "/documents", "headers": auth}},
        {"request": {"method": "GET", "url": base + "/invoices/100", "headers": auth}},
        {"request": {"method": "POST", "url": base + "/orgs/o-50/members", "headers": auth,
                     "postData": {"mimeType": "application/json",
                                  "text": json.dumps({"userId": "u-3003"})}}},
    ]}}


def c_nondestructive():
    import mock_server
    from bacscan.config import Config
    from bacscan import cli, ingest
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        before = copy.deepcopy(mock_server.Handler.state)
        cfg = Config(_full_cfg(base, destructive=False))
        tmp = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8")
        json.dump(_har(base), tmp)
        tmp.close()
        reqs = [r for r in ingest.from_har(tmp.name) if cfg.host_allowed(r["url"])]
        types = {f["type"] for f in cli.run(cfg, reqs)["findings"]}
        after = mock_server.Handler.state
        assert before == after, "MUTATION en mode non-destructif: %s -> %s" % (before, after)
        for forbidden in ("bopla", "bfla-asymmetry", "privilege-escalation"):
            assert forbidden not in types, "%s ne doit pas apparaitre (non-destructif)" % forbidden
        assert "idor" in types, "idor (GET) doit fonctionner en non-destructif"
        assert "existence-leakage" in types, "leakage doit fonctionner en non-destructif"
    finally:
        httpd.shutdown()


def c_smoke_cli():
    import mock_server
    from bacscan import cli
    httpd = mock_server.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        outdir = tempfile.mkdtemp()
        cfg = _full_cfg(base, destructive=True)
        cfg["output"] = {"findings_db": os.path.join(outdir, "findings.json"),
                         "report_md": os.path.join(outdir, "report.md")}
        cfgp = os.path.join(outdir, "cfg.yaml")
        yaml.safe_dump(cfg, open(cfgp, "w"))
        harp = os.path.join(outdir, "t.har")
        json.dump(_har(base), open(harp, "w"))
        rc = cli.main(["--config", cfgp, "--har", harp])
        assert rc == 1, "exit code attendu 1 (vuln trouvee), recu %r" % rc
        assert os.path.exists(cfg["output"]["findings_db"]), "findings.json absent"
        assert os.path.exists(cfg["output"]["report_md"]), "report.md absent"
        data = json.load(open(cfg["output"]["findings_db"], encoding="utf-8"))
        assert data.get("findings"), "findings vide"
    finally:
        httpd.shutdown()


def c_scope_guard():
    from bacscan.config import Config, ConfigError
    try:
        Config({"base_url": "https://evil.example.com",
                "scope": {"allow_hosts": ["api.example.com"]}, "profiles": []})
    except ConfigError:
        return
    raise AssertionError("scope guard n'a pas refuse un hote hors perimetre")


def c_triage():
    import test_triage
    assert test_triage.main() == 0


def c_hardening():
    import test_hardening
    assert test_hardening.main() == 0


def c_pyflakes():
    import importlib.util
    import subprocess
    if importlib.util.find_spec("pyflakes") is None:
        print("    (pyflakes absent -> check ignore ; pip install pyflakes)")
        return
    r = subprocess.run(
        [sys.executable, "-m", "pyflakes",
         os.path.join(ROOT, "bacscan"), os.path.join(ROOT, "tests"),
         os.path.join(ROOT, "tools")],
        capture_output=True, text=True)
    assert r.returncode == 0, "pyflakes a trouve des problemes:\n" + (r.stdout + r.stderr)


def main():
    run("1. compile", c_compile)
    run("2. imports", c_imports)
    run("3. e2e (6 classes)", c_e2e)
    run("4. advanced (auth/dynamic/declaratif/graphql)", c_advanced)
    run("5. non-destructif (zero mutation)", c_nondestructive)
    run("6. smoke-cli (findings.json + report.md)", c_smoke_cli)
    run("7. scope-guard", c_scope_guard)
    run("8. triage (faux positifs + log)", c_triage)
    run("9. hardening (retry/redirect/erreurs/redaction/audit)", c_hardening)
    run("10. pyflakes (code mort)", c_pyflakes)

    fails = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print("RESULTAT: %d/%d checks PASS" % (len(RESULTS) - len(fails), len(RESULTS)))
    for name, ok, err in fails:
        print("  FAIL %s : %s" % (name, err))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
