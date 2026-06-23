#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_role_escalation.py
========================
Active checker for a *Broken Access Control* / *privilege-escalation* class of
vulnerability on REST APIs that expose a "promote a user to an administrative
role on a resource" endpoint, e.g.:

    POST {base}/{resource}/administrators/{userId}     (often with no body)

Hypothesis under test
---------------------
If the backend does NOT re-check that the caller is ALREADY a legitimate
administrator of *that* resource, an authenticated low-privilege user may:
  - VERTICAL escalation : promote themselves to admin of their own resource;
  - HORIZONTAL escalation (IDOR) : promote themselves on someone else's
    resource by changing the resource id in the path.

This is CWE-269 (Improper Privilege Management) coupled with CWE-639 (IDOR),
mapping to OWASP WSTG-ATHZ-02 / ATHZ-04 and OWASP Top 10 "Broken Access Control".

>>> AUTHORIZED USE ONLY <<<
--------------------------
This is an ACTIVE testing tool. Run it ONLY against systems you are explicitly
authorized to test (your own lab, a CTF, or a signed pentest engagement).
Unauthorized use against third-party systems is illegal.

Safety design
-------------
- NON-DESTRUCTIVE by default: the mutating promotion request is sent only with
  --exploit, and the state is restored automatically (rollback) afterwards.
- Scope guard: --allow-host is REQUIRED. Any host other than the one you
  declare is refused before any request is sent.
- IDOR (--idor-resource): only the HTTP status code is observed. The tool never
  reads or alters another resource's data -- the response code is the proof.

Verdict matrix
--------------
    vertical 2xx + role becomes <admin> + idor 2xx -> CRITICAL (escalation + IDOR)
    vertical 2xx + role becomes <admin> + idor 4xx -> HIGH (vertical real, ownership OK)
    vertical 2xx + no observable effect            -> INVESTIGATE (200 no-op?)
    vertical 401/403                               -> REFUTED (server enforces)

Endpoint templates
------------------
Paths are templated with {resource} and {user}. Defaults are generic REST
conventions -- override them to match the target API:

    --list-path      GET, lists members and their roles   default /{resource}/members
    --promote-path   the escalation endpoint              default /{resource}/administrators/{user}
    --rollback-path  restores the prior state             default /{resource}/members/{user}

Examples
--------
  # safe phases only (no mutation): baseline + controls
  python check_role_escalation.py \
    --base-url https://api.lab.local --allow-host api.lab.local \
    --jwt eyJ... --user-id u-123 --resource-id r-456

  # full vertical test (mutating, auto rollback) + IDOR (status code only)
  python check_role_escalation.py \
    --base-url https://api.lab.local --allow-host api.lab.local \
    --jwt eyJ... --user-id u-123 --resource-id r-456 \
    --exploit --idor-resource r-OTHER

  # JSON-Patch style rollback instead of DELETE
  python check_role_escalation.py ... --exploit \
    --rollback-method PATCH --rollback-path /{resource} \
    --rollback-body '[{"op":"remove","path":"/members/{user}"}]'

Output: a verdict + a timestamped JSON evidence log (evidence_*.json).
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    sys.stderr.write(
        "[ERROR] The 'requests' module is required. Install it with:\n"
        "    pip install requests\n"
    )
    sys.exit(2)


# --------------------------------------------------------------------------- #
# Output (ASCII only: keeps it portable across legacy Windows code pages)
# --------------------------------------------------------------------------- #
def banner(txt):
    print("\n" + "=" * 70)
    print(txt)
    print("=" * 70)


def section(txt):
    print("\n--- " + txt + " ---")


def info(txt):
    print("[i]   " + txt)


def ok(txt):
    print("[OK]  " + txt)


def warn(txt):
    print("[!]   " + txt)


def vuln(txt):
    print("[VULN] " + txt)


def fail(txt):
    print("[X]   " + txt)


# --------------------------------------------------------------------------- #
# Evidence log
# --------------------------------------------------------------------------- #
class Evidence:
    """Accumulates each request/response for the report (timestamped proof)."""

    def __init__(self):
        self.events = []

    def log(self, label, method, url, status, elapsed_ms, note="", body_excerpt=""):
        self.events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "label": label,
            "method": method,
            "url": url,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "note": note,
            "response_excerpt": body_excerpt,
        })

    def dump(self, path, meta):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"meta": meta, "events": self.events}, fh,
                      indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Templating + HTTP helpers
# --------------------------------------------------------------------------- #
def render(template, resource, user):
    """Substitute {resource} and {user} placeholders in a path or body string."""
    if template is None:
        return None
    return template.replace("{resource}", str(resource)).replace("{user}", str(user))


def short_body(resp, limit=600):
    try:
        txt = resp.text or ""
    except Exception:
        return "<unreadable body>"
    txt = txt.replace("\n", " ").replace("\r", " ")
    return txt[:limit] + (" ...[truncated]" if len(txt) > limit else "")


def do_request(session, ev, label, method, url, *, auth_header=None,
               data=None, json_body=None, extra_headers=None,
               timeout=20, verify=True):
    """Send a request, log it, return (resp | None, error | None)."""
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    if extra_headers:
        headers.update(extra_headers)
    t0 = time.time()
    try:
        resp = session.request(method, url, headers=headers, data=data,
                               json=json_body, timeout=timeout, verify=verify)
    except RequestException as exc:
        ev.log(label, method, url, None, int((time.time() - t0) * 1000),
               note="NETWORK ERROR: " + str(exc))
        fail("%s -> network error: %s" % (label, exc))
        return None, str(exc)
    elapsed = int((time.time() - t0) * 1000)
    ev.log(label, method, url, resp.status_code, elapsed,
           body_excerpt=short_body(resp))
    return resp, None


def normalize_members(data):
    """Reduce a heterogeneous member-list response to a list of dict entries."""
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        for key in ("members", "users", "value", "items",
                    "content", "results", "data"):
            v = data.get(key)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
        emb = data.get("_embedded")
        if isinstance(emb, dict):
            for v in emb.values():
                if isinstance(v, list):
                    return [e for e in v if isinstance(e, dict)]
        # fallback generique : toute valeur liste-de-dicts (cle metier non standard)
        for v in data.values():
            if isinstance(v, list) and any(isinstance(e, dict) for e in v):
                return [e for e in v if isinstance(e, dict)]
        if "role" in data:
            return [data]
    return []


def find_caller_role(entries, user_id, role_field):
    """Locate the caller's entry (by user_id) and return (present, role)."""
    uid = str(user_id)
    for e in entries:
        if uid in json.dumps(e, ensure_ascii=False):
            return True, e.get(role_field)
    return False, None


# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
def phase_baseline(session, ev, args):
    """Read-only: current role of the caller on the resource."""
    section("Phase 1 - Baseline (read-only): current role on the resource")
    url = args.base_url + render(args.list_path, args.resource_id, args.user_id)
    resp, err = do_request(session, ev, "baseline.list", "GET", url,
                           auth_header=args.auth, timeout=args.timeout,
                           verify=not args.insecure)
    if err or resp is None:
        warn("Could not read member list (baseline unavailable).")
        return {"reachable": False}
    info("HTTP %d on GET member list" % resp.status_code)
    if resp.status_code == 401:
        warn("401: invalid/expired JWT? Re-authenticate and copy a fresh token.")
        return {"reachable": True, "status": 401}
    role, present = None, False
    try:
        present, role = find_caller_role(
            normalize_members(resp.json()), args.user_id, args.role_field)
    except ValueError:
        warn("Non-JSON response: cannot auto-extract the role.")
    if present:
        info("Caller found in member list, current role = %r" % role)
        if role == args.admin_role:
            warn("You are ALREADY %r on this resource: the vertical test is "
                 "meaningless here. Pick a resource where you are NOT admin."
                 % args.admin_role)
    else:
        info("Caller NOT found among members (not a member, or different id "
             "format).")
    return {"reachable": True, "status": resp.status_code,
            "present": present, "role": role}


def phase_controls(session, ev, args):
    """Controls that make the result interpretable."""
    section("Phase 2 - Controls (make the test interpretable)")
    promote_url = args.base_url + render(args.promote_path, args.resource_id,
                                         args.user_id)

    # Control A: no auth -> should be 401 (endpoint requires authentication).
    info("Control A: promote WITHOUT Authorization (expect 401)")
    respA, _ = do_request(session, ev, "control.no_auth", args.promote_method,
                          promote_url, data=args.promote_body or b"",
                          timeout=args.timeout, verify=not args.insecure)
    codeA = respA.status_code if respA is not None else None
    if codeA == 401:
        ok("401 confirmed: a later 200 with a JWT will be meaningful.")
    elif codeA in (403, 405):
        info("%s: endpoint rejects/ignores unauthenticated calls (acceptable)." % codeA)
    elif codeA in (200, 204):
        vuln("%s WITHOUT AUTH: endpoint is open without authentication!" % codeA)
    elif codeA is not None:
        warn("Unexpected status without auth: %d" % codeA)

    # Control B: bogus resource id -> distinguishes 'not found' from 'forbidden'.
    bogus = "BOGUS_REF_%d" % int(time.time())
    bogus_url = args.base_url + render(args.promote_path, bogus, args.user_id)
    info("Control B: promote on a non-existent resource %s (with JWT)" % bogus)
    respB, _ = do_request(session, ev, "control.bogus_ref", args.promote_method,
                          bogus_url, auth_header=args.auth,
                          data=args.promote_body or b"",
                          timeout=args.timeout, verify=not args.insecure)
    codeB = respB.status_code if respB is not None else None
    if codeB == 404:
        info("404: server resolves the object (it checks the resource exists).")
    elif codeB == 403:
        info("403: access control BEFORE object resolution (good defensive sign).")
    elif codeB in (200, 204):
        vuln("%s on a bogus resource: very suspicious (creates from nothing)." % codeB)
    elif codeB is not None:
        info("Status on bogus resource: %d" % codeB)
    return {"no_auth": codeA, "bogus_ref": codeB}


def phase_vertical(session, ev, args):
    """Main test: vertical escalation on YOUR OWN resource."""
    section("Phase 3 - VERTICAL test (mutating): self-promote on YOUR resource")
    url = args.base_url + render(args.promote_path, args.resource_id, args.user_id)
    warn("Mutating test in progress (promotion). Rollback scheduled in phase 6.")
    resp, err = do_request(session, ev, "vertical.promote", args.promote_method,
                           url, auth_header=args.auth,
                           data=args.promote_body or b"",
                           timeout=args.timeout, verify=not args.insecure)
    if err or resp is None:
        return {"status": None}
    code = resp.status_code
    info("HTTP %d on promote (own resource)" % code)
    if code in (200, 204):
        vuln("%d: promotion ACCEPTED without prior-admin check (confirm via "
             "impact in phase 4)." % code)
    elif code in (401, 403):
        ok("%d: server re-checks privileges -> finding REFUTED (vertical)." % code)
    elif code in (400, 422):
        warn("%d: a body/format is expected. Compare with a legitimate request "
             "(--promote-body) and re-test." % code)
    elif code == 409:
        warn("409: conflict (already admin?). Check your initial state (baseline).")
    return {"status": code}


def phase_impact(session, ev, args):
    """A 200 is not enough: prove the real effect (role becomes admin)."""
    section("Phase 4 - IMPACT confirmation: did the role actually change?")
    url = args.base_url + render(args.list_path, args.resource_id, args.user_id)
    resp, err = do_request(session, ev, "impact.list", "GET", url,
                           auth_header=args.auth, timeout=args.timeout,
                           verify=not args.insecure)
    if err or resp is None:
        return {"role": None, "is_admin": False}
    try:
        present, role = find_caller_role(
            normalize_members(resp.json()), args.user_id, args.role_field)
    except ValueError:
        warn("Non-JSON response: verify the role field manually.")
        return {"role": None, "is_admin": False}
    info("Caller role after test = %r" % role)
    is_admin = (role == args.admin_role)
    if is_admin:
        vuln("ESCALATION MATERIALIZED: role == %r." % args.admin_role)
    else:
        info("No observable effect on the role (possible 200 no-op).")
    return {"role": role, "is_admin": is_admin, "present": present}


def phase_idor(session, ev, args):
    """Horizontal IDOR test -- STATUS CODE ONLY."""
    section("Phase 5 - HORIZONTAL test (IDOR): status code only")
    warn("Golden rule: on someone else's resource, observe ONLY the status "
         "code. Never read or modify the third party's data.")
    url = args.base_url + render(args.promote_path, args.idor_resource,
                                 args.user_id)
    resp, err = do_request(session, ev, "idor.promote_other", args.promote_method,
                           url, auth_header=args.auth,
                           data=args.promote_body or b"",
                           timeout=args.timeout, verify=not args.insecure)
    if err or resp is None:
        return {"status": None}
    code = resp.status_code
    info("HTTP %d on promote (third-party resource)" % code)
    if code in (200, 204):
        vuln("%d: IDOR + ESCALATION on a third-party resource. STOP exploiting. "
             "Rollback in phase 6, touch nothing else." % code)
    elif code in (401, 403):
        ok("%d: ownership enforced -> IDOR REFUTED." % code)
    elif code == 404:
        info("404: unknown/unresolved resource (confirm it exists).")
    return {"status": code}


def phase_rollback(session, ev, args, targets):
    """Restore state (remove the promoted membership)."""
    section("Phase 6 - Cleanup / state restoration")
    if args.no_rollback:
        warn("--no-rollback: automatic rollback DISABLED. Restore manually:")
        for ref in targets:
            rb_url = args.base_url + render(args.rollback_path, ref, args.user_id)
            print("      %s %s  body=%s"
                  % (args.rollback_method, rb_url,
                     render(args.rollback_body, ref, args.user_id) or "<none>"))
        return
    if not targets:
        info("No successful promotion -> nothing to restore.")
        return
    warn("Make sure --rollback-path/--rollback-method match how your API undoes "
         "the promotion; otherwise restore manually (baseline is in the JSON).")
    for ref in targets:
        url = args.base_url + render(args.rollback_path, ref, args.user_id)
        body_str = render(args.rollback_body, ref, args.user_id)
        json_body = None
        extra = {}
        if body_str:
            try:
                json_body = json.loads(body_str)
                extra["Content-Type"] = "application/json"
            except ValueError:
                warn("Rollback body is not valid JSON; sending as raw.")
        resp, err = do_request(session, ev, "rollback.remove",
                               args.rollback_method, url, auth_header=args.auth,
                               json_body=json_body,
                               data=None if json_body is not None else (body_str or None),
                               extra_headers=extra or None,
                               timeout=args.timeout, verify=not args.insecure)
        if resp is not None and resp.status_code in (200, 204):
            ok("Rollback applied on resource %s (HTTP %d)." % (ref, resp.status_code))
        else:
            code = resp.status_code if resp is not None else "ERR"
            warn("Rollback NOT confirmed on %s (HTTP %s) -> verify/restore manually."
                 % (ref, code))
        # Re-verify state
        vurl = args.base_url + render(args.list_path, ref, args.user_id)
        vresp, _ = do_request(session, ev, "rollback.verify", "GET", vurl,
                              auth_header=args.auth, timeout=args.timeout,
                              verify=not args.insecure)
        if vresp is not None:
            try:
                _, role = find_caller_role(
                    normalize_members(vresp.json()), args.user_id, args.role_field)
                if role == args.admin_role:
                    warn("WARNING: still %r on %s after rollback!"
                         % (args.admin_role, ref))
                else:
                    ok("State restored on %s (current role = %r)." % (ref, role))
            except ValueError:
                pass


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #
def compute_verdict(vertical, impact, idor, admin_role):
    v = vertical.get("status")
    is_admin = impact.get("is_admin") if impact else None
    i = idor.get("status") if idor else None

    if v in (401, 403):
        return ("REFUTED",
                "Server re-checks privileges (HTTP %s): vertical escalation blocked." % v)
    if v in (200, 204):
        if is_admin and i in (200, 204):
            return ("CRITICAL",
                    "Vertical escalation CONFIRMED (role=%s) AND horizontal IDOR "
                    "(HTTP %s on a third-party resource)." % (admin_role, i))
        if is_admin and i in (401, 403):
            return ("HIGH",
                    "Vertical escalation REAL (role=%s); ownership enforced on the "
                    "IDOR path (HTTP %s)." % (admin_role, i))
        if is_admin and i is None:
            return ("HIGH (IDOR untested)",
                    "Vertical escalation REAL (role=%s). IDOR not evaluated "
                    "(re-run with --idor-resource to decide CRITICAL/HIGH)." % admin_role)
        return ("INVESTIGATE",
                "HTTP %s on promote but no observable effect (200 no-op?). Verify "
                "the member list and the id format manually." % v)
    if v is None:
        return ("INCONCLUSIVE",
                "Vertical test not run (safe mode: add --exploit) or network error.")
    return ("INCONCLUSIVE",
            "Unexpected vertical status (HTTP %s): inspect the response body/format." % v)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Active checker for role-promotion Broken Access Control / "
                    "IDOR (CWE-269 + CWE-639). AUTHORIZED USE ONLY.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--base-url", required=True,
                   help="Exact API base URL, without the resource path "
                        "(e.g. https://api.lab.local).")
    p.add_argument("--allow-host", required=True,
                   help="Authorized host (scope guard). Any other host is "
                        "refused. REQUIRED: forces a conscious scope decision.")
    p.add_argument("--jwt", required=True,
                   help="Caller bearer token (without the 'Bearer ' prefix).")
    p.add_argument("--user-id", required=True,
                   help="Caller's user id (as it appears in the member list).")
    p.add_argument("--resource-id", required=True,
                   help="Id of YOUR resource (the one you test against).")
    p.add_argument("--idor-resource", default=None,
                   help="Id of ANOTHER resource (IDOR test, status code only). "
                        "Requires --exploit.")
    p.add_argument("--exploit", action="store_true",
                   help="Allow mutating requests (vertical + IDOR). Without it: "
                        "safe phases only (baseline + controls).")
    p.add_argument("--no-rollback", action="store_true",
                   help="Do NOT restore state automatically (discouraged).")
    # Endpoint templates ({resource} and {user} are substituted)
    p.add_argument("--list-path", default="/{resource}/members",
                   help="GET path listing members and roles. Default /{resource}/members")
    p.add_argument("--promote-path", default="/{resource}/administrators/{user}",
                   help="Promotion endpoint. Default /{resource}/administrators/{user}")
    p.add_argument("--promote-method", default="POST",
                   help="HTTP method for promotion. Default POST")
    p.add_argument("--promote-body", default=None,
                   help="Optional request body for promotion (default: none).")
    p.add_argument("--role-field", default="role",
                   help="Member field holding the role. Default 'role'")
    p.add_argument("--admin-role", default="ADMINISTRATOR",
                   help="Role value that means 'admin'. Default 'ADMINISTRATOR'")
    p.add_argument("--rollback-method", default="DELETE",
                   help="HTTP method to undo the promotion. Default DELETE")
    p.add_argument("--rollback-path", default="/{resource}/members/{user}",
                   help="Path to undo the promotion. Default /{resource}/members/{user}")
    p.add_argument("--rollback-body", default=None,
                   help="Optional rollback body (e.g. a JSON-Patch document).")
    p.add_argument("--insecure", action="store_true",
                   help="Do not verify the TLS certificate (local proxy).")
    p.add_argument("--timeout", type=int, default=20,
                   help="HTTP timeout in seconds (default 20).")
    p.add_argument("--out", default=None,
                   help="Evidence JSON path (default: auto-timestamped).")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    args.base_url = args.base_url.rstrip("/")
    args.auth = "Bearer " + args.jwt.replace("Bearer ", "").strip()

    # Scope guard: refuse any host other than --allow-host.
    host = urlsplit(args.base_url).hostname or ""
    if host != args.allow_host:
        fail("Host '%s' is outside the authorized scope ('%s'). Aborting."
             % (host, args.allow_host))
        return 2
    if urlsplit(args.base_url).scheme != "https":
        warn("Non-HTTPS URL: avoid except behind an explicit local proxy.")

    banner("Role-escalation checker (Broken Access Control / IDOR) - host %s" % host)
    info("Base URL : %s" % args.base_url)
    info("resource=%s  user=%s  admin-role=%s"
         % (args.resource_id, args.user_id, args.admin_role))
    info("Mode : %s" % ("EXPLOIT (mutating, auto rollback)" if args.exploit
                        else "SAFE (read + controls, no mutation)"))
    if args.insecure:
        warn("TLS verification DISABLED (--insecure).")
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore
        except Exception:
            pass

    ev = Evidence()
    session = requests.Session()
    session.headers.update({"User-Agent": "role-escalation-checker"})

    base = phase_baseline(session, ev, args)
    controls = phase_controls(session, ev, args)

    vertical, impact, idor = {"status": None}, {"is_admin": False}, {"status": None}
    promoted = []

    if args.exploit:
        if base.get("role") == args.admin_role:
            warn("Already %r: vertical test skipped (not meaningful)." % args.admin_role)
        else:
            vertical = phase_vertical(session, ev, args)
            if vertical.get("status") in (200, 204):
                promoted.append(args.resource_id)
                impact = phase_impact(session, ev, args)
        if args.idor_resource:
            idor = phase_idor(session, ev, args)
            if idor.get("status") in (200, 204):
                promoted.append(args.idor_resource)
        phase_rollback(session, ev, args, promoted)
    else:
        section("Mutating phases SKIPPED (safe mode)")
        info("Add --exploit to run the promotion test (on your own resource, "
             "with automatic rollback) and conclude on the vulnerability.")

    label, detail = compute_verdict(vertical, impact, idor, args.admin_role)
    banner("VERDICT: " + label)
    print(detail)
    print("\nVerdict matrix:")
    print("  vertical 2xx + role=%s + idor 2xx -> CRITICAL" % args.admin_role)
    print("  vertical 2xx + role=%s + idor 4xx -> HIGH" % args.admin_role)
    print("  vertical 2xx + no effect            -> INVESTIGATE")
    print("  vertical 401/403                    -> REFUTED")

    out = args.out or ("evidence_%s.json"
                       % datetime.now().strftime("%Y%m%d_%H%M%S"))
    meta = {
        "host": host, "base_url": args.base_url,
        "resource_id": args.resource_id, "user_id": args.user_id,
        "idor_resource": args.idor_resource, "exploit": args.exploit,
        "baseline": base, "controls": controls,
        "vertical": vertical, "impact": impact, "idor": idor,
        "verdict": label, "verdict_detail": detail,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    ev.dump(out, meta)
    print("\n[i]   Evidence log written: %s" % out)
    warn("Anonymize the JWT in the evidence before archiving/sharing.")

    return 1 if label.startswith(("CRITICAL", "HIGH")) else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.stderr.write("\n[interrupted]\n")
        sys.exit(130)
