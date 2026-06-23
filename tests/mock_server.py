# -*- coding: utf-8 -*-
"""Mock API VOLONTAIREMENT vulnerable pour tester bacscan (local uniquement).

Classes :
  - GET  /orgs/{org}/members            : BOLA
  - POST /orgs/{org}/administrators/{u} : privesc
  - GET  /admin/users                   : BFLA force-browse
  - PUT/PATCH /orgs/{org}/settings 403 / DELETE 204 : BFLA asymetrie
  - POST /orgs/{org}/members {role}     : BOPLA
  - GET  /secrets/{id}                  : existence leakage (403/404)
Avance :
  - POST /oauth/token                   : refresh -> access_token (auth pluggable)
  - GET  /csrf-token (Set-Cookie) + POST /csrf-protected (exige X-CSRF-Token) : CSRF
  - GET  /documents (liste sur-exposee) + /documents/{id} : IDOR dynamique (chainage)
  - GET  /invoices/{n}                  : IDOR sequentiel
  - POST /graphql                       : introspection + IDOR via variables

Tokens "expired-*" -> 401 (pour tester le refresh OAuth).
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
USER = re.compile(r"^/users/([^/]+)/?$")
DOCUMENTS = re.compile(r"^/documents/?$")
DOCUMENT = re.compile(r"^/documents/([^/]+)/?$")
INVOICE = re.compile(r"^/invoices/([^/]+)/?$")
# Forme "promotion admin sans corps + role dans une liste imbriquee a cle metier custom"
# (reproduit la mecanique du cas d'origine : POST sans body, role lu dans une cle non standard).
GADMIN = re.compile(r"^/svc/orgs/([^/]+)/admins/([^/]+)/?$")
GGRANTS = re.compile(r"^/svc/orgs/([^/]+)/grants/?$")
GGRANT = re.compile(r"^/svc/orgs/([^/]+)/grants/([^/]+)/?$")

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
        a = self.headers.get("Authorization") or ""
        return bool(a) and "expired" not in a  # token "expired-*" => non authentifie

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def _send(self, code, obj=None, cookie=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        else:
            self.send_header("Content-Length", "0")
        self.end_headers()
        if body:
            self.wfile.write(body)

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        if self.path == "/flaky429":  # 429 au 1er appel puis 200 -> teste le retry
            type(self).flaky = getattr(type(self), "flaky", 0) + 1
            if type(self).flaky == 1:
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(200, {"ok": True})
        if self.path == "/always500":
            return self._send(500)
        if self.path == "/redirect":  # 302 vers une ressource du meme hote
            self.send_response(302)
            self.send_header("Location", "/public/banner")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/public/banner":  # ressource PUBLIQUE (pas d'auth) -> piege a FP
            return self._send(200, {"banner": "welcome"})
        if not self._authed():
            return self._send(401)
        if self.path == "/empty":  # 2xx mais corps vide -> oracle faible
            return self._send(200)
        if self.path == "/csrf-token":
            return self._send(200, {"ok": True}, cookie="XSRF-TOKEN=csrf123; Path=/")
        if self.path == "/admin/users":  # VULN BFLA
            return self._send(200, {"users": sorted(
                {u for org in self.state.values() for u in org})})
        if DOCUMENTS.match(self.path):  # liste sur-exposee (source d'IDs)
            return self._send(200, {"documents": [
                {"docId": "d-1", "owner": "u-2002"},
                {"docId": "d-2", "owner": "u-1001"}]})
        m = DOCUMENT.match(self.path)
        if m:  # VULN BOLA objet
            return self._send(200, {"docId": m.group(1), "content": "secret-doc"})
        m = INVOICE.match(self.path)
        if m:  # VULN BOLA numerique (enumeration)
            return self._send(200, {"invoiceId": m.group(1), "amount": 42})
        m = USER.match(self.path)
        if m:  # VULN BOLA objet utilisateur
            return self._send(200, {"userId": m.group(1), "email": "x@y.z"})
        m = MEMBERS.match(self.path)
        if m:  # VULN BOLA
            members = self.state.get(m.group(1), {})
            return self._send(200, {"members": [
                {"userId": u, "role": d["role"]} for u, d in members.items()]})
        m = GGRANTS.match(self.path)
        if m:  # role dans une cle metier custom "grants" / champ "privilege"
            grants = self.orgs2.get(m.group(1), {})
            return self._send(200, {"grants": [
                {"principal": u, "privilege": d["privilege"]} for u, d in grants.items()]})
        m = SECRET.match(self.path)
        if m:  # existence leakage : 403 si existe, 404 sinon
            return self._send(403 if m.group(1) in SECRETS else 404)
        return self._send(404)

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        if self.path == "/oauth/token":  # pas d'auth requise
            body = self._read_json()
            if body.get("refresh_token"):
                return self._send(200, {"access_token": "fresh-1"})
            return self._send(401)
        if not self._authed():
            return self._send(401)
        if self.path == "/graphql":
            return self._graphql(self._read_json())
        if self.path == "/csrf-protected":
            if self.headers.get("X-CSRF-Token") == "csrf123":
                return self._send(200, {"ok": True})
            return self._send(403)
        m = ADMIN.match(self.path)
        if m:  # VULN privesc
            self.state.setdefault(m.group(1), {})[m.group(2)] = {"role": "ADMINISTRATOR"}
            return self._send(204)
        m = MEMBERS.match(self.path)
        if m:  # VULN BOPLA : honore le role fourni
            body = self._read_json()
            user = body.get("userId", "u-new")
            role = body.get("role", "CONTRIBUTOR")
            self.state.setdefault(m.group(1), {})[user] = {"role": role}
            return self._send(201, {"userId": user, "role": role})
        m = GADMIN.match(self.path)
        if m:  # VULN privesc, POST SANS corps (mecanique du cas d'origine)
            self.orgs2.setdefault(m.group(1), {})[m.group(2)] = {"privilege": "ADMINISTRATOR"}
            return self._send(204)
        return self._send(404)

    def _graphql(self, body):
        q = body.get("query", "") if isinstance(body, dict) else ""
        if "__schema" in q:  # VULN : introspection activee
            return self._send(200, {"data": {"__schema": {"types": [{"name": "User"}]}}})
        if "user" in q:  # VULN BOLA : aucune verif d'ownership sur l'id
            vid = (body.get("variables") or {}).get("id")
            return self._send(200, {"data": {"user": {"id": vid, "email": "x@y.z"}}})
        return self._send(200, {"data": None, "errors": [{"message": "unknown"}]})

    # ----------------------------------------------------------------- PUT/PATCH/DELETE
    def do_PUT(self):
        if not self._authed():
            return self._send(401)
        return self._send(403 if SETTINGS.match(self.path) else 404)

    def do_PATCH(self):
        if not self._authed():
            return self._send(401)
        return self._send(403 if SETTINGS.match(self.path) else 404)

    def do_DELETE(self):
        if not self._authed():
            return self._send(401)
        if SETTINGS.match(self.path):
            return self._send(204)  # VULN BFLA asymetrie
        m = MEMBER.match(self.path)
        if m:
            self.state.get(m.group(1), {}).pop(m.group(2), None)
            return self._send(204)
        m = GGRANT.match(self.path)
        if m:  # rollback
            self.orgs2.get(m.group(1), {}).pop(m.group(2), None)
            return self._send(204)
        return self._send(404)


def start(host="127.0.0.1", port=0):
    Handler.state = make_state()
    Handler.flaky = 0
    # etat "grants" : role initial non-admin, reponse a cle metier custom
    Handler.orgs2 = {"o-mine": {"u-me": {"privilege": "REQUESTER"}}}
    httpd = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


if __name__ == "__main__":
    s = start(port=8799)
    print("mock vulnerable sur", s.server_address)
    import time
    while True:
        time.sleep(1)
