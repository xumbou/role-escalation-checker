# -*- coding: utf-8 -*-
"""Auto-detection : HAR live -> engagement.yaml genere (mode assiste).

Decode les JWT (user-id), detecte promote-path / list-path / admin-role /
role-field, templatise les chemins ({resource}/{user}) et genere un
`engagement.yaml` STRICTEMENT conforme a config.Config (charge en fin via
config.load_config pour garantir sa validite).

NON DESTRUCTIF / READ-ONLY : ce module n'emet AUCUNE requete reseau. Il ne fait
qu'analyser un HAR deja capture. Aucun secret n'est jamais affiche en clair
(redact.py pour toute sortie console).

Usage autorise uniquement (lab / CTF / engagement signe).
"""
import base64
import json
import re
from collections import Counter
from urllib.parse import urlsplit

from . import ingest
from .redact import redact

# --------------------------------------------------------------------------- #
# Regex de detection
# --------------------------------------------------------------------------- #
# promote-path : segments "administratifs" ; le score reflete la specificite.
_PROMOTE_SEG = re.compile(
    r"(?i)/(administrators?|admins?|roles?|members?|grants?|permissions?)(/|$)")
_PROMOTE_SCORE = [
    (re.compile(r"(?i)/administrators?(/|$)"), 5),
    (re.compile(r"(?i)/admins?(/|$)"), 4),
    (re.compile(r"(?i)/grants?(/|$)"), 3),
    (re.compile(r"(?i)/permissions?(/|$)"), 3),
    (re.compile(r"(?i)/roles?(/|$)"), 2),
    (re.compile(r"(?i)/members?(/|$)"), 1),
]
_LIST_SEG = re.compile(r"(?i)/(members|users|roles)(/|$)")
_ROLE_KEY = re.compile(r"(?i)^(role|roles|authority|authorities|type|level)$")
_ADMIN_VAL = re.compile(r"(?i)(admin|administrator|owner|superuser|root|manager)")

# Segments "user-like" : si un id suit un de ces segments -> {user}, sinon {resource}.
_USER_SEG = re.compile(r"(?i)^(users?|members?|administrators?|people|accounts?|profiles?)$")

# Reconnaissance d'un segment-id (a templatiser).
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEXLONG = re.compile(r"^[0-9a-fA-F]{16,64}$")
_INT = re.compile(r"^\d+$")
# id "prefixe" courant : u-1001, o-50, r-456, org_77...
_PREFIXED = re.compile(r"(?i)^[a-z]{1,6}[-_]?\d{1,}$")
# Segment de version d'API (v1, v2, v10...) : ce n'est PAS un id -> ne pas templatiser.
_VERSION = re.compile(r"(?i)^v\d+$")

# Claims candidats pour le user-id (ordre = priorite).
_USERID_CLAIMS = ["sub", "userId", "user_id", "uid", "preferred_username", "oid", "upn"]


def _is_id_segment(seg):
    if _VERSION.match(seg):  # /api/v1/... : 'v1' est une version, pas une ressource
        return False
    return bool(_UUID.match(seg) or _HEXLONG.match(seg)
                or _INT.match(seg) or _PREFIXED.match(seg))


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def _b64url_decode(seg):
    seg = seg + "=" * (-len(seg) % 4)  # corrige le padding
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def decode_jwt_payload(token):
    """Decode le PAYLOAD d'un JWT (2e segment) SANS verifier la signature.

    Renvoie un dict (claims) ou None si ce n'est pas un JWT decodable.
    Ne leve jamais : un token opaque n'est pas un JWT.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001  -- token opaque/non-JWT : jamais d'echec dur
        return None
    return payload if isinstance(payload, dict) else None


def _extract_user_id(claims):
    """1er claim candidat present (ordre _USERID_CLAIMS) -> (claim, valeur)."""
    for c in _USERID_CLAIMS:
        if c in claims and isinstance(claims[c], (str, int)):
            return c, str(claims[c])
    return None, None


def harvest_tokens(reqs):
    """Collecte les bearer tokens distincts depuis les headers Authorization.

    Renvoie une liste ordonnee (1er vu d'abord) de tokens uniques. Ne renvoie
    JAMAIS le token a la console : c'est l'appelant qui decide (et redacte)."""
    seen, tokens = set(), []
    for r in reqs:
        for name, value in (r.get("headers") or {}).items():
            if name.lower() == "authorization" and value:
                m = re.match(r"(?i)^bearer\s+(\S+)$", value.strip())
                tok = m.group(1) if m else value.strip()
                if tok and tok not in seen:
                    seen.add(tok)
                    tokens.append(tok)
    return tokens


# --------------------------------------------------------------------------- #
# Templatisation des chemins
# --------------------------------------------------------------------------- #
def templatize_path(path):
    """Remplace les segments-id par {user} (apres un segment user-like) ou {resource}.

    Strategie : le 1er id rencontre apres un segment user-like devient {user} ;
    le 1er autre id (collection ressource) devient {resource}. Les id suivants
    de meme nature reutilisent le meme placeholder.
    """
    segs = path.split("/")
    out = []
    prev = ""
    used_user = used_resource = False
    for seg in segs:
        if seg and _is_id_segment(seg):
            if _USER_SEG.match(prev):
                out.append("{user}")
                used_user = True
            elif not used_resource:
                out.append("{resource}")
                used_resource = True
            elif not used_user:
                out.append("{user}")
                used_user = True
            else:
                out.append("{resource}")
            prev = seg
            continue
        out.append(seg)
        if seg:
            prev = seg
    return "/".join(out)


def _path_of(url):
    return urlsplit(url).path or "/"


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #
def _score_promote(path):
    for rx, sc in _PROMOTE_SCORE:
        if rx.search(path):
            return sc
    return 0


def detect_promote_path(reqs):
    """Meilleur candidat promote-path (POST/PUT/PATCH sur segment admin).

    Renvoie (template, score, raw_path) ou (None, 0, None)."""
    best = (None, 0, None)
    for r in reqs:
        if r.get("method", "").upper() not in ("POST", "PUT", "PATCH"):
            continue
        path = _path_of(r["url"])
        if not _PROMOTE_SEG.search(path):
            continue
        score = _score_promote(path)
        if score > best[1]:
            best = (templatize_path(path), score, path)
    return best


def _looks_like_role_list(body_text):
    """True si le corps JSON est une liste (ou contient une liste) d'objets a role."""
    try:
        data = json.loads(body_text)
    except (ValueError, TypeError):
        return False, []
    if isinstance(data, dict):
        items = None
        for k in ("members", "users", "results", "data", "items"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
        if items is None:
            items = next((v for v in data.values() if isinstance(v, list)), None)
    elif isinstance(data, list):
        items = data
    else:
        items = None
    if not items:
        return False, []
    role_keys = []
    for e in items:
        if isinstance(e, dict):
            for k in e:
                if _ROLE_KEY.match(k):
                    role_keys.append(k)
    return (bool(role_keys), role_keys)


def detect_list_path(full_reqs):
    """GET dont le path matche members|users|roles ET dont la reponse est une
    liste d'objets a role. Renvoie (template, raw_path) ou (None, None)."""
    for r in full_reqs:
        if r.get("method", "").upper() != "GET":
            continue
        path = _path_of(r["url"])
        if not _LIST_SEG.search(path):
            continue
        body = r.get("resp_body")
        if not body:
            continue
        ok, _ = _looks_like_role_list(body)
        if ok:
            return templatize_path(path), path
    return None, None


def detect_role_field_and_admin(full_reqs):
    """Scanne les reponses JSON : cles de role + valeurs admin.

    Renvoie (role_field, admin_role) ou (None, None)."""
    role_values = {}  # cle de role -> Counter(valeurs)

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if _ROLE_KEY.match(k) and isinstance(v, (str, int)):
                    role_values.setdefault(k, Counter())[str(v)] += 1
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for r in full_reqs:
        body = r.get("resp_body")
        if not body:
            continue
        try:
            walk(json.loads(body))
        except (ValueError, TypeError):
            continue

    # On privilegie la cle qui porte une valeur "admin".
    for field, vals in role_values.items():
        admin_vals = [v for v in vals if _ADMIN_VAL.search(v)]
        if admin_vals:
            # valeur admin la plus frequente
            admin_role = max(admin_vals, key=lambda v: vals[v])
            return field, admin_role
    # Sinon : une cle de role existe mais sans valeur "admin" reconnue.
    if role_values:
        field = next(iter(role_values))
        return field, None
    return None, None


def detect_base_host(reqs):
    """Host le plus frequent (servira de base_url + allow_hosts)."""
    hosts = Counter(urlsplit(r["url"]).hostname for r in reqs
                    if urlsplit(r["url"]).hostname)
    if not hosts:
        return None
    return hosts.most_common(1)[0][0]


def _scheme_for(reqs, host):
    for r in reqs:
        sp = urlsplit(r["url"])
        if sp.hostname == host and sp.scheme:
            return sp.scheme
    return "https"


# --------------------------------------------------------------------------- #
# Analyse complete
# --------------------------------------------------------------------------- #
def analyze(har_path):
    """Analyse un HAR -> dict de detections (sans IO d'ecriture, sans reseau)."""
    full_reqs = ingest.from_har_full(har_path)
    reqs = [{"method": r["method"], "url": r["url"], "headers": r["headers"]}
            for r in full_reqs]

    host = detect_base_host(reqs)
    scheme = _scheme_for(reqs, host) if host else "https"
    base_url = "%s://%s" % (scheme, host) if host else None

    tokens = harvest_tokens(reqs)
    profiles = []
    for i, tok in enumerate(tokens):
        claims = decode_jwt_payload(tok) or {}
        claim, uid = _extract_user_id(claims)
        profiles.append({
            "token": tok, "user_id": uid, "user_id_claim": claim,
            "is_jwt": bool(claims),
        })

    promote_tpl, promote_score, promote_raw = detect_promote_path(reqs)
    list_tpl, list_raw = detect_list_path(full_reqs)
    role_field, admin_role = detect_role_field_and_admin(full_reqs)

    return {
        "host": host, "base_url": base_url,
        "profiles": profiles,
        "promote_path": promote_tpl, "promote_score": promote_score,
        "promote_raw": promote_raw,
        "list_path": list_tpl, "list_raw": list_raw,
        "role_field": role_field, "admin_role": admin_role,
        "n_requests": len(reqs),
    }


def _confidence(detections):
    """Confiance par detection (high/medium/low) pour le recap."""
    conf = {}
    sc = detections.get("promote_score") or 0
    conf["promote_path"] = "high" if sc >= 4 else ("medium" if sc >= 2 else
                                                   ("low" if sc else "none"))
    conf["list_path"] = "high" if detections.get("list_path") else "none"
    conf["admin_role"] = "high" if detections.get("admin_role") else "none"
    conf["role_field"] = ("high" if detections.get("role_field") else "none")
    conf["user_id"] = ("high" if (detections["profiles"]
                                  and detections["profiles"][0].get("user_id"))
                       else "none")
    return conf


# --------------------------------------------------------------------------- #
# Generation du YAML
# --------------------------------------------------------------------------- #
def _q(v):
    """Quote YAML minimaliste pour une scalaire string (toujours entre guillemets)."""
    if v is None:
        return "null"
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % s


def build_engagement_yaml(detections, engagement="assisted-engagement"):
    """Genere le texte d'un engagement.yaml conforme a config.Config.

    Le 1er profil token = attacker (non-admin). Bloc role_escalation pre-rempli.
    safety.destructive force a false. En-tete = avertissement secrets.
    """
    host = detections.get("host") or "REPLACE_HOST"
    base_url = detections.get("base_url") or ("https://%s" % host)
    profiles = detections.get("profiles") or []

    lines = []
    lines.append("# engagement.yaml genere par `bacscan suggest` (mode assiste).")
    lines.append("# !!! CONTIENT DES SECRETS (tokens JWT) -- NE PAS COMMITTER !!!")
    lines.append("# VERIFIE scope.allow_hosts et les paths avant tout scan.")
    lines.append("# Usage autorise uniquement (lab / CTF / engagement signe).")
    lines.append("engagement: %s" % _q(engagement))
    lines.append("base_url: %s" % _q(base_url))
    lines.append("scope:")
    lines.append("  allow_hosts: [%s]  # TODO verifier le perimetre" % _q(host))
    lines.append("auth:")
    lines.append('  header: "Authorization"')
    lines.append('  prefix: "Bearer "')
    lines.append("profiles:")
    if not profiles:
        lines.append("  # TODO aucun token detecte : ajoute au moins un profil authentifie")
        lines.append("  - name: %s" % _q("attacker"))
        lines.append("    token: null  # TODO renseigner ${ATTACKER_JWT}")
    for i, p in enumerate(profiles):
        name = "attacker" if i == 0 else ("user%d" % i)
        lines.append("  - name: %s" % _q(name))
        lines.append("    auth:")
        lines.append('      type: "bearer"')
        # le token reel est inclus (le YAML contient des secrets, en-tete d'alerte)
        lines.append("      token: %s" % _q(p["token"]))
        uid = p.get("user_id")
        if uid:
            lines.append("    ids: { user_id: %s }" % _q(uid))
        else:
            lines.append("    ids: { user_id: null }  # TODO verifier (JWT sans claim user-id)")
    lines.append("probes: [idor, idor_dynamic, bfla, leakage]")
    lines.append("impact_plugins: [role_escalation]")
    lines.append("role_escalation:")
    if detections.get("list_path"):
        lines.append("  list_path: %s" % _q(detections["list_path"]))
    else:
        lines.append('  list_path: "/{resource}/members"  # TODO verifier (non detecte)')
    if detections.get("promote_path"):
        lines.append("  promote_path: %s" % _q(detections["promote_path"]))
    else:
        lines.append('  promote_path: "/{resource}/administrators/{user}"  # TODO verifier (non detecte)')
    if detections.get("admin_role"):
        lines.append("  admin_role: %s" % _q(detections["admin_role"]))
    else:
        lines.append('  admin_role: "ADMINISTRATOR"  # TODO verifier (non detecte)')
    if detections.get("role_field"):
        lines.append("  role_field: %s" % _q(detections["role_field"]))
    else:
        lines.append('  role_field: "role"  # TODO verifier (non detecte)')
    lines.append("output:")
    lines.append('  findings_db: "findings/assisted.json"')
    lines.append('  report_md: "reports/assisted.md"')
    lines.append('  triage_log: "reports/assisted-triage.log"')
    lines.append('  audit_log: "reports/assisted-audit.json"')
    lines.append("safety:")
    lines.append("  destructive: false  # NE PAS passer a true sans autorisation explicite")
    lines.append("  rollback: auto")
    lines.append("")
    return "\n".join(lines)


def write_engagement(detections, out_path, engagement="assisted-engagement"):
    """Ecrit le YAML genere (0600 : contient des secrets) puis le VALIDE via
    config.load_config. Renvoie le Config charge."""
    import os

    text = build_engagement_yaml(detections, engagement=engagement)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(out_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    from . import config as C
    return C.load_config(out_path)  # leve ConfigError si non conforme


# --------------------------------------------------------------------------- #
# Recap console (redacte)
# --------------------------------------------------------------------------- #
def format_recap(detections):
    """Table de recap des detections (secrets redactes)."""
    conf = _confidence(detections)
    rows = []
    rows.append("[suggest] %d requete(s) analysee(s) ; host = %s"
                % (detections["n_requests"], detections.get("host")))
    p0 = (detections["profiles"] or [{}])[0]
    uid = p0.get("user_id") or "(non detecte)"
    rows.append("  user-id (attacker) : %-22s [%s]" % (uid, conf["user_id"]))
    rows.append("  promote_path       : %-22s [%s]"
                % (detections.get("promote_path") or "(non detecte)", conf["promote_path"]))
    rows.append("  list_path          : %-22s [%s]"
                % (detections.get("list_path") or "(non detecte)", conf["list_path"]))
    rows.append("  admin_role         : %-22s [%s]"
                % (detections.get("admin_role") or "(non detecte)", conf["admin_role"]))
    rows.append("  role_field         : %-22s [%s]"
                % (detections.get("role_field") or "(non detecte)", conf["role_field"]))
    rows.append("  profils (tokens)   : %d detecte(s)" % len(detections["profiles"]))
    rows.append("  AVERTISSEMENT : verifie scope.allow_hosts et les paths avant tout scan.")
    rows.append("  AVERTISSEMENT : le YAML genere contient des SECRETS -- ne pas committer.")
    return redact("\n".join(rows))
