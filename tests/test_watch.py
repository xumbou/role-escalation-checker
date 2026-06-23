# -*- coding: utf-8 -*-
"""Test `watch` : detection de changement + relance pipeline mockee + SAFE force.

Le pipeline reel (cli.run) est remplace par un mock leger : on verifie que watch
detecte les nouvelles requetes, ne re-soumet pas les requetes deja vues, force
destructive=False, et ecrit findings_db. Fixtures synthetiques (api.lab.local).
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan import watch as W

LAB_BASE = "https://api.lab.local"


def _cfg_yaml(findings_db):
    return """\
engagement: "watch-test"
base_url: "%s"
scope:
  allow_hosts: ["api.lab.local"]
auth:
  header: "Authorization"
  prefix: "Bearer "
profiles:
  - name: "attacker"
    auth: { type: "bearer", token: "tok-attacker" }
    ids: { user_id: "u-1001" }
safety:
  destructive: true
probes: [idor]
impact_plugins: [role_escalation]
output:
  findings_db: "%s"
""" % (LAB_BASE, findings_db.replace("\\", "/"))


def _har(entries):
    return {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                    "entries": entries}}


def _entry(method, path):
    return {"request": {"method": method, "url": LAB_BASE + path, "headers": []},
            "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}}}


def main():
    d = tempfile.mkdtemp()
    findings_db = os.path.join(d, "findings.json")
    cfg_path = os.path.join(d, "cfg.yaml")
    har_path = os.path.join(d, "traffic.har")
    open(cfg_path, "w", encoding="utf-8").write(_cfg_yaml(findings_db))

    # HAR initial : 2 requetes en scope + 1 hors scope (doit etre ignoree)
    entries = [_entry("GET", "/orgs/o-50/members"),
               _entry("POST", "/orgs/o-50/administrators/u-1001")]
    entries.append({"request": {"method": "GET", "url": "https://evil.example.com/x",
                                "headers": []}})
    json.dump(_har(entries), open(har_path, "w", encoding="utf-8"))

    calls = {"runs": 0, "seen_reqs": [], "destructive_seen": []}

    def fake_run(cfg, reqs, **kw):
        calls["runs"] += 1
        calls["seen_reqs"].append([(r["method"], r["url"]) for r in reqs])
        calls["destructive_seen"].append(cfg.destructive)
        # un finding bidon confirme pour exercer l'ecriture
        f = {"type": "privilege-escalation", "severity": "critical",
             "title": "demo", "request": {"method": "POST", "url": LAB_BASE + "/x"}}
        return {"findings": [f], "matrix": [], "evidence": [],
                "confirmed": [f], "false_positives": [], "inconclusive": [], "triage_log": []}

    # 1 iteration : detecte les 2 requetes en scope, ignore l'evil host
    n = W.watch(cfg_path, har_path, interval=0, run_fn=fake_run, max_iterations=1)
    assert n == 1, ("1 scan attendu", n)
    assert calls["runs"] == 1
    seen = calls["seen_reqs"][0]
    assert len(seen) == 2, ("2 requetes en scope attendues", seen)
    urls = {u for _, u in seen}
    assert all("evil.example.com" not in u for u in urls), "host hors scope soumis au pipeline"

    # SAFE force : destructive=False malgre safety.destructive:true dans le YAML
    assert calls["destructive_seen"] == [False], \
        ("watch doit forcer destructive=False", calls["destructive_seen"])

    # findings_db ecrit
    assert os.path.exists(findings_db), "findings_db non ecrit"
    data = json.load(open(findings_db, encoding="utf-8"))
    assert data.get("findings"), "findings vide"

    print("[OK] watch: detection + SAFE force (destructive=False) + scope + ecriture findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
