# -*- coding: utf-8 -*-
"""Configuration d'engagement (YAML) + garde-fou de scope.

Le YAML d'engagement est le coeur de la reutilisabilite : le moteur est generique,
seul ce fichier change d'une mission a l'autre.
"""
import os
from urllib.parse import urlsplit

try:
    import yaml
except ImportError:
    yaml = None


class ConfigError(Exception):
    pass


class Profile:
    """Une identite de test (anon / low-priv / victime / admin)."""

    def __init__(self, name, token=None, ids=None):
        self.name = name
        self.token = token
        self.ids = ids or {}

    @property
    def is_anon(self):
        return not self.token


class Config:
    def __init__(self, data):
        self.engagement = data.get("engagement", "unnamed")
        self.base_url = (data.get("base_url") or "").rstrip("/")
        scope = data.get("scope") or {}
        self.allow_hosts = set(scope.get("allow_hosts") or [])
        auth = data.get("auth") or {}
        self.auth_header = auth.get("header", "Authorization")
        self.auth_prefix = auth.get("prefix", "Bearer ")
        self.profiles = [
            Profile(p["name"], _resolve_env(p.get("token")), p.get("ids"))
            for p in (data.get("profiles") or [])
        ]
        safety = data.get("safety") or {}
        self.destructive = bool(safety.get("destructive", False))
        self.rollback = safety.get("rollback", "auto")
        self.rate_limit_rps = float(safety.get("rate_limit_rps", 0) or 0)
        self.probes = data.get("probes") or []
        self.impact_plugins = data.get("impact_plugins") or []
        out = data.get("output") or {}
        self.findings_db = out.get("findings_db")
        self.report_md = out.get("report_md")
        # blocs de config specifiques aux plugins (ex: role_escalation)
        self.plugin_conf = {k: data[k] for k in ("role_escalation",) if k in data}
        self._validate()

    def _validate(self):
        if not self.base_url:
            raise ConfigError("base_url manquant")
        if not self.allow_hosts:
            raise ConfigError("scope.allow_hosts manquant (garde-fou obligatoire)")
        host = urlsplit(self.base_url).hostname
        if host not in self.allow_hosts:
            raise ConfigError("base_url host %r hors allow_hosts %r"
                              % (host, sorted(self.allow_hosts)))

    def host_allowed(self, url):
        return (urlsplit(url).hostname or "") in self.allow_hosts

    def profile(self, name):
        for p in self.profiles:
            if p.name == name:
                return p
        return None

    def attacker(self):
        """Profil attaquant par defaut : 1er profil authentifie non-admin."""
        for p in self.profiles:
            if p.token and p.name != "admin":
                return p
        return None


def _resolve_env(val):
    """Resout ${VAR} depuis l'environnement (ne jamais ecrire les tokens en clair)."""
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        return os.environ.get(val[2:-1])
    return val


def load_config(path):
    if yaml is None:
        raise ConfigError("PyYAML requis : pip install pyyaml")
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return Config(data)
