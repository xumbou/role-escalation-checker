# -*- coding: utf-8 -*-
"""Mock API VOLONTAIREMENT vulnerable pour tester bacscan (local uniquement).

Vulns plantees :
  - GET  /orgs/{org}/members             : BOLA (lit n'importe quel org)
  - POST /orgs/{org}/administrators/{u}  : privesc (promotion admin sans check)
  - GET  /admin/users                    : BFLA (fonction admin accessible a tout authed)
  - PUT/PATCH /orgs/{org}/settings -> 403 mais DELETE -> 204 : BFLA asymetrie
  - POST /orgs/{org}/members {role}      : BOPLA (mass-assignment du role)
  - GET  /secrets/{id}                   : existence leakage (403 si existe, 404 sinon)
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MEMBERS = re.compile(r"^/orgs/([^/]+)/members/?$")
MEMBER = re.compile(r"^/orgs/([^/]+)/members/([^/]+)/?$")
ADMIN = re.compile(r"^/orgs/([^/]+)/administrators/([^/]+)/?$")
SETTINGS = re.compile(r"^/orgs/([^/]+)/settings/?$")
SECRET = re.compile(r"^/secrets/([^/]+)/?$")

SECRETS = {"s-1"}


def make_state():
    return {
        "o-50": {"u-1001": {"role": "CONTRIBUTOR"}},
        "o-77": {"u-2002": {"role": "CONTRIBUTOR"}},
    }


class Handler(BaseHTTPRequestHandler):
    state = None

    def log_message(self, *a):
        pass

    def _authed(self):
        return bool(self.headers.get("Authorization"))

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def _send(self, code, obj=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if not self._authed():
            return self._send(401)
        if self.path == "/admin/users":
            # VULN BFLA : fonction admin ouverte a tout utilisateur authentifie
            return self._send(200, {"users": sorted(
                {u for org in self.state.values() for u in org})})
        m = MEMBERS.match(self.path)
        if m:
            members = self.state.get(m.group(1), {})  # VULN BOLA : pas de check d'org
            return self._send(200, {"members": [
                {"userId": u, "role": d["role"]} for u, d in members.items()]})
        m = SECRET.match(self.path)
        if m:
            # existence leakage : 403 si la ressource existe, 404 sinon
            return self._send(403 if m.group(1) in SECRETS else 404)
        return self._send(404)

    def do_POST(self):
        if not self._authed():
            return self._send(401)
        m = ADMIN.match(self.path)
        if m:
            org, user = m.group(1), m.group(2)
            self.state.setdefault(org, {})[user] = {"role": "ADMINISTRATOR"}  # VULN privesc
            return self._send(204)
        m = MEMBERS.match(self.path)
        if m:
            body = self._read_json()
            user = body.get("userId", "u-new")
            role = body.get("role", "CONTRIBUTOR")  # VULN BOPLA : honore le role fourni
            self.state.setdefault(m.group(1), {})[user] = {"role": role}
            return self._send(201, {"userId": user, "role": role})
        return self._send(404)

    def do_PUT(self):
        if not self._authed():
            return self._send(401)
        if SETTINGS.match(self.path):
            return self._send(403)  # protege
        return self._send(404)

    def do_PATCH(self):
        if not self._authed():
            return self._send(401)
        if SETTINGS.match(self.path):
            return self._send(403)  # protege
        return self._send(404)

    def do_DELETE(self):
        if not self._authed():
            return self._send(401)
        if SETTINGS.match(self.path):
            return self._send(204)  # VULN BFLA asymetrie : DELETE non protege
        m = MEMBER.match(self.path)
        if m:
            self.state.get(m.group(1), {}).pop(m.group(2), None)
            return self._send(204)
        return self._send(404)


def start(host="127.0.0.1", port=0):
    Handler.state = make_state()
    httpd = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


if __name__ == "__main__":
    s = start(port=8799)
    print("mock vulnerable sur", s.server_address)
    import time
    while True:
        time.sleep(1)
