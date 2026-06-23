# -*- coding: utf-8 -*-
"""Test de la logique HAR pure (append/flush + scope) SANS mitmproxy.

On teste HarWriter (ecriture atomique, filtrage de scope, HAR toujours valide) et
CaptureAddon avec des objets `flow` FACTICES qui miment l'API mitmproxy. Aucun
import de mitmproxy n'est requis ici.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bacscan import capture, ingest


# --- objets factices mimant l'API mitmproxy --------------------------------- #
class FakeHeaders(dict):
    def items(self):
        return list(super().items())


class FakeMsg:
    def __init__(self, headers=None, text=""):
        self.headers = FakeHeaders(headers or {})
        self._text = text

    def get_text(self, strict=False):
        return self._text


class FakeRequest(FakeMsg):
    def __init__(self, method, url, headers=None, text=""):
        super().__init__(headers, text)
        self.method = method
        self.url = url
        self.host = url.split("/")[2]


class FakeResponse(FakeMsg):
    def __init__(self, status, headers=None, text=""):
        super().__init__(headers, text)
        self.status_code = status


class FakeFlow:
    def __init__(self, request, response=None):
        self.request = request
        self.response = response


LAB = "api.lab.local"


def main():
    out = tempfile.NamedTemporaryFile(suffix=".har", delete=False)
    out.close()
    writer = capture.HarWriter(out.name, allow_hosts=[LAB], flush_every=1)
    writer.flush()  # HAR vide valide immediatement

    # fichier 0600 (best-effort sous Windows ; sous POSIX strict)
    if os.name == "posix":
        mode = os.stat(out.name).st_mode & 0o777
        assert mode == 0o600, "HAR doit etre en 0600, vu %o" % mode

    addon = capture.CaptureAddon(writer)

    # 1) flow EN SCOPE : doit etre capture, request + response
    f_in = FakeFlow(
        FakeRequest("POST", "https://api.lab.local/orgs/o-50/administrators/u-1001",
                    headers={"Authorization": "Bearer eyJfake", "Content-Type": "application/json"},
                    text='{"x":1}'),
        FakeResponse(200, headers={"Content-Type": "application/json"},
                     text='{"role":"ADMINISTRATOR"}'))
    addon.response(f_in)

    # 2) flow HORS SCOPE : doit etre IGNORE (jamais ecrit)
    f_out = FakeFlow(
        FakeRequest("GET", "https://evil.example.com/orgs/o-50/members",
                    headers={"Authorization": "Bearer secret"}),
        FakeResponse(200, text="[]"))
    addon.response(f_out)

    assert addon.count == 1, ("1 seul flow en scope attendu", addon.count)
    assert addon.skipped == 1, ("1 flow hors scope ignore attendu", addon.skipped)

    # Le HAR sur disque est un HAR 1.2 VALIDE et relisable par ingest
    har = json.load(open(out.name, encoding="utf-8"))
    assert har["log"]["version"] == "1.2", har["log"].get("version")
    assert len(har["log"]["entries"]) == 1, "seul le flow en scope doit etre present"

    e = har["log"]["entries"][0]
    assert e["request"]["method"] == "POST"
    assert e["request"]["url"].startswith("https://api.lab.local/")
    assert e["response"]["status"] == 200
    assert "ADMINISTRATOR" in e["response"]["content"]["text"]

    # parse via from_har (request) et from_har_full (response)
    reqs = ingest.from_har(out.name)
    assert len(reqs) == 1 and reqs[0]["method"] == "POST"
    full = ingest.from_har_full(out.name)
    assert full[0]["status"] == 200
    assert "ADMINISTRATOR" in (full[0]["resp_body"] or "")

    # Aucun host hors scope ne doit apparaitre dans le fichier
    raw = open(out.name, encoding="utf-8").read()
    assert "evil.example.com" not in raw, "fuite d'un host hors scope dans le HAR"

    # HAR malforme -> ingest tolere (log vide), ne crash pas
    bad = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8")
    bad.write("{ this is : not json ]")
    bad.close()
    assert ingest.from_har(bad.name) == []
    assert ingest.from_har_full(bad.name) == []

    os.unlink(out.name)
    os.unlink(bad.name)
    print("[OK] capture HAR: append/flush valide, scope filtre, HAR malforme tolere")
    return 0


if __name__ == "__main__":
    sys.exit(main())
