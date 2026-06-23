# -*- coding: utf-8 -*-
"""Mock API VOLONTAIREMENT vulnerable (BOLA + escalade de role) pour tester bacscan.

A n'utiliser qu'en local. Deux vulns plantees :
  - GET  /orgs/{org}/members            : lit n'importe quel org (BOLA, pas de check d'appartenance)
  - POST /orgs/{org}/administrators/{u} : promeut admin sans verifier que l'appelant l'est (privesc)
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MEMBERS = re.compile(r"^/orgs/([^/]+)/members/?$")
MEMBER = re.compile(r"^/orgs/([^/]+)/members/([^/]+)/?$")
ADMIN = re.compile(r"^/orgs/([^/]+)/administrators/([^/]+)/?$")


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
        m = MEMBERS.match(self.path)
        if m:
            # VULN BOLA : aucun controle d'appartenance a l'org demande.
            members = self.state.get(m.group(1), {})
            return self._send(200, {"members": [
                {"userId": u, "role": d["role"]} for u, d in members.items()]})
        return self._send(404)

    def do_POST(self):
        if not self._authed():
            return self._send(401)
        m = ADMIN.match(self.path)
        if m:
            org, user = m.group(1), m.group(2)
            # VULN PRIVESC : aucune verif que l'appelant est admin de cet org.
            self.state.setdefault(org, {})[user] = {"role": "ADMINISTRATOR"}
            return self._send(204)
        return self._send(404)

    def do_DELETE(self):
        if not self._authed():
            return self._send(401)
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
