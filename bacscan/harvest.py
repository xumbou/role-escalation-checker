# -*- coding: utf-8 -*-
"""Extraction d'identifiants depuis des reponses JSON (chainage dynamique d'IDOR).

On collecte recursivement les valeurs des cles 'id-like' (id, *_id, *Id, ref, uuid...)
et, si presente, la cle 'owner' de l'objet englobant -> permet de cibler les objets
qui n'appartiennent PAS a l'attaquant.
"""
import re

ID_KEYS = re.compile(r"(?i)(id$|_id$|ref$|reference$|uuid$|guid$|^pk$|number$|slug$)")
OWNER_KEYS = ("owner", "ownerId", "userId", "user", "createdBy", "author")


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
                if isinstance(v, (str, int)) and ID_KEYS.search(k):
                    found.append({"key": k, "val": str(v), "owner": owner})
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(obj)
    return found
