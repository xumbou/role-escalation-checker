# -*- coding: utf-8 -*-
"""Extraction d'identifiants depuis des reponses JSON (chainage dynamique d'IDOR).

On collecte recursivement les valeurs des cles 'id-like' (id, *_id, *Id, ref, uuid...)
et, si presente, la cle 'owner' de l'objet englobant -> permet de cibler les objets
qui n'appartiennent PAS a l'attaquant.
"""
import re

ID_KEYS = re.compile(
    r"(?i)(id$|_id$|ref$|reference$|uuid$|guid$|^pk$|number$|slug$|title$|"
    r"code$|handle$|sku$|^key$|key_id$|token_id$)")
OWNER_KEYS = ("owner", "ownerId", "userId", "user", "createdBy", "author", "user_id")

# Valeurs ressemblant a un identifiant meme si la cle n'est pas "id-like"
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEXLONG = re.compile(r"^[0-9a-fA-F]{16,64}$")


def looks_like_id(v):
    s = str(v)
    return bool(_UUID.match(s) or _HEXLONG.match(s) or (s.isdigit() and len(s) <= 12))


def harvest(obj):
    """Renvoie [{key, val, owner}] trouves recursivement dans `obj`."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            owner = None
            for ok in OWNER_KEYS:
                v = node.get(ok)
                if isinstance(v, (str, int)):
                    owner = str(v)
                    break
            for k, v in node.items():
                if isinstance(v, (str, int)) and (ID_KEYS.search(k) or looks_like_id(v)):
                    found.append({"key": k, "val": str(v), "owner": owner})
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(obj)
    return found
