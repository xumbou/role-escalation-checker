# -*- coding: utf-8 -*-
"""Capture live (proxy -> HAR 1.2) pour le mode assiste.

Deux couches :
  - logique HAR PURE (HarWriter) : construit/append/flush un HAR 1.2 valide, sans
    aucune dependance a mitmproxy -> testable en isolation, ecriture atomique 0600 ;
  - addon mitmproxy (CaptureAddon) + lanceur (run_capture) : import mitmproxy
    UNIQUEMENT ici, derriere un try/except (dependance optionnelle).

Garde-fous (NON NEGOCIABLES) :
  - SCOPE : seuls les flows dont le host est dans allow_hosts sont ecrits. Tout
    host hors scope est ignore (jamais ecrit, jamais relaye comme preuve).
  - SECRETS : le HAR brut contient des tokens/cookies/mots de passe -> fichier en
    0600 ; toute sortie console passe par redact.py (jamais un token en clair).
  - READ-ONLY : la capture n'emet AUCUNE requete propre, ne mute rien.

Usage autorise uniquement (lab / CTF / engagement signe).
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .redact import redact

HAR_VERSION = "1.2"
CREATOR = {"name": "bacscan-capture", "version": "1.0"}

# Message d'install affiche si mitmproxy manque (dependance optionnelle).
_MITM_HINT = (
    "mitmproxy n'est pas installe. Installe l'extra de capture :\n"
    "  pipx inject role-escalation-checker mitmproxy\n"
    "  # ou : pip install mitmproxy")


def host_of(url):
    """Hostname d'une URL (vide si non parsable). Utilitaire de scope."""
    return urlsplit(url or "").hostname or ""


def _headers_to_har(headers):
    """dict ou liste (name,value) -> liste HAR [{'name','value'}]."""
    out = []
    if isinstance(headers, dict):
        items = headers.items()
    else:
        # objet type multidict (mitmproxy) : items() renvoie des paires
        try:
            items = headers.items()
        except AttributeError:
            items = []
    for name, value in items:
        if name is None:
            continue
        name = str(name)
        if name.startswith(":"):  # pseudo-headers HTTP/2
            continue
        out.append({"name": name, "value": "" if value is None else str(value)})
    return out


def build_entry(method, url, req_headers=None, req_body=None, req_mime=None,
                status=0, resp_headers=None, resp_body=None, resp_mime=None,
                started=None):
    """Construit une entree HAR 1.2 (request + response). Pure, sans IO.

    `req_body` / `resp_body` sont du texte (str) ; bytes sont decodes en best-effort.
    """
    def _as_text(b):
        if b is None:
            return None
        if isinstance(b, bytes):
            return b.decode("utf-8", "replace")
        return str(b)

    req = {
        "method": str(method or "GET").upper(),
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": _headers_to_har(req_headers),
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": -1,
    }
    rb = _as_text(req_body)
    if rb is not None:
        req["postData"] = {"mimeType": req_mime or "application/octet-stream",
                           "text": rb}

    resp = {
        "status": int(status or 0),
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "headers": _headers_to_har(resp_headers),
        "cookies": [],
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": -1,
        "content": {
            "size": len(_as_text(resp_body) or "") if resp_body is not None else 0,
            "mimeType": resp_mime or "application/octet-stream",
            "text": _as_text(resp_body) if resp_body is not None else "",
        },
    }
    return {
        "startedDateTime": started or datetime.now(timezone.utc).isoformat(),
        "time": 0,
        "request": req,
        "response": resp,
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }


def _open_secure(path):
    """Ouvre `path` en ecriture binaire avec permissions restreintes (0600).

    Sur POSIX, os.open garantit le mode des la creation. Sous Windows, le mode
    est applique en best-effort via os.chmod (le modele ACL differe ; le
    .gitignore reste la garantie principale contre le commit accidentel).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return os.fdopen(fd, "wb")


class HarWriter:
    """Buffer d'entrees HAR + flush atomique vers un fichier 0600.

    Filtre de scope INTEGRE : add_flow / add_entry ignorent silencieusement tout
    host hors `allow_hosts`. Le wrapper {"log": {...}} est toujours reecrit
    entierement -> le fichier sur disque est TOUJOURS un HAR valide.
    """

    def __init__(self, path, allow_hosts, flush_every=1):
        self.path = path
        self.allow_hosts = set(allow_hosts or [])
        self.flush_every = max(1, int(flush_every))
        self.entries = []
        self._dirty = 0

    # -- scope -------------------------------------------------------------- #
    def in_scope(self, url):
        return host_of(url) in self.allow_hosts

    # -- ajout -------------------------------------------------------------- #
    def add_entry(self, entry):
        """Ajoute une entree HAR deja construite si elle est en scope.

        Renvoie True si ajoutee, False si ignoree (hors scope / invalide)."""
        if not isinstance(entry, dict):
            return False
        url = (entry.get("request") or {}).get("url")
        if not url or not self.in_scope(url):
            return False
        self.entries.append(entry)
        self._dirty += 1
        if self._dirty >= self.flush_every:
            self.flush()
        return True

    def add(self, **kw):
        """Construit une entree depuis des champs bruts puis l'ajoute (si en scope)."""
        url = kw.get("url")
        if not url or not self.in_scope(url):
            return False
        return self.add_entry(build_entry(**kw))

    # -- IO ----------------------------------------------------------------- #
    def to_har(self):
        return {"log": {"version": HAR_VERSION, "creator": dict(CREATOR),
                        "entries": list(self.entries)}}

    def flush(self):
        """Reecrit atomiquement le HAR complet (tmp + os.replace), fichier 0600."""
        data = json.dumps(self.to_har(), ensure_ascii=False, indent=2)
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".har-", dir=directory)
        try:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._dirty = 0


def _safe_console(msg):
    """Affiche un message en ASCII-safe + redacte (jamais de secret en clair)."""
    msg = redact(msg)
    try:
        sys.stdout.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(msg.encode("ascii", "replace").decode("ascii") + "\n")


# --------------------------------------------------------------------------- #
# Addon mitmproxy (import optionnel)
# --------------------------------------------------------------------------- #
def _import_mitmproxy():
    """Verifie que mitmproxy est disponible, sinon leve ImportError + hint d'install."""
    import importlib.util
    if importlib.util.find_spec("mitmproxy") is None:
        raise ImportError(_MITM_HINT)


class CaptureAddon:
    """Addon mitmproxy : hook `response` -> append HAR (scope-filtre).

    Ne depend PAS de l'import mitmproxy (recoit des objets `flow` au runtime).
    Testable avec des flows factices (cf. tests/test_capture_har.py).
    """

    def __init__(self, writer):
        self.writer = writer
        self.count = 0
        self.skipped = 0

    def response(self, flow):
        """Hook mitmproxy : appele quand une reponse complete arrive."""
        try:
            req = flow.request
            url = req.url
        except AttributeError:
            return
        if not self.writer.in_scope(url):
            self.skipped += 1
            return
        resp = getattr(flow, "response", None)
        req_mime = req.headers.get("content-type") if hasattr(req, "headers") else None
        req_body = None
        try:
            req_body = req.get_text(strict=False)
        except (AttributeError, TypeError, ValueError):
            req_body = getattr(req, "text", None)
        status, resp_headers, resp_body, resp_mime = 0, None, None, None
        if resp is not None:
            status = getattr(resp, "status_code", 0)
            resp_headers = getattr(resp, "headers", None)
            if hasattr(resp, "headers"):
                resp_mime = resp.headers.get("content-type")
            try:
                resp_body = resp.get_text(strict=False)
            except (AttributeError, TypeError, ValueError):
                resp_body = getattr(resp, "text", None)
        entry = build_entry(
            method=req.method, url=url,
            req_headers=getattr(req, "headers", None),
            req_body=req_body, req_mime=req_mime,
            status=status, resp_headers=resp_headers,
            resp_body=resp_body, resp_mime=resp_mime)
        if self.writer.add_entry(entry):
            self.count += 1


def run_capture(allow_hosts, port=8080, har_out="traffic.har", flush_every=1):
    """Lance le proxy mitmproxy et capture le trafic en scope vers `har_out`.

    Bloquant jusqu'a Ctrl-C. Necessite mitmproxy (extra `[capture]`).
    """
    _import_mitmproxy()
    import asyncio
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    allow_hosts = set(allow_hosts or [])
    if not allow_hosts:
        raise ValueError("au moins un --allow-host est requis (garde-fou de scope)")

    writer = HarWriter(har_out, allow_hosts, flush_every=flush_every)
    writer.flush()  # cree immediatement un HAR vide valide, en 0600

    _safe_console("[capture] proxy en ecoute sur 127.0.0.1:%d" % port)
    _safe_console("[capture] configure ton client/navigateur sur ce proxy HTTP(S)")
    _safe_console("[capture] CA mitmproxy : visite http://mitm.it une fois le proxy actif")
    _safe_console("[capture] scope capte (hosts autorises) : %s" % ", ".join(sorted(allow_hosts)))
    _safe_console("[capture] HAR live (0600) -> %s   (Ctrl-C pour arreter)" % har_out)
    _safe_console("[capture] SECRETS : ce HAR contient des tokens/cookies -- ne pas committer")

    addon = CaptureAddon(writer)

    async def _amain():
        opts = options.Options(listen_host="127.0.0.1", listen_port=int(port))
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(addon)
        try:
            await master.run()
        finally:
            master.shutdown()

    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass
    finally:
        writer.flush()
        _safe_console("[capture] arret. %d entree(s) capturee(s), %d hors scope ignoree(s) -> %s"
                      % (addon.count, addon.skipped, har_out))
    return addon.count
