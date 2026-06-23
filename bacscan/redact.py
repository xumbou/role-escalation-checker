# -*- coding: utf-8 -*-
"""Redaction des donnees sensibles dans les corps de reponse stockes (sorties/audit).

Masque : secrets connus (tokens des profils), emails, et valeurs de champs sensibles
(password/secret/token...). Ne touche PAS aux marqueurs fonctionnels (ex: role=ADMINISTRATOR)
pour ne pas casser la detection.
"""
import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_SENSITIVE_FIELD = re.compile(
    r'("(?:password|passwd|pwd|secret|token|access_token|refresh_token|authorization|'
    r'api[_-]?key|ssn|credit_card)"\s*:\s*")[^"]*(")', re.IGNORECASE)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}")


def redact(text, secrets=()):
    if not text:
        return text
    for s in secrets:
        if s and len(str(s)) >= 6:
            text = text.replace(str(s), "[REDACTED-SECRET]")
    text = _SENSITIVE_FIELD.sub(r"\1[REDACTED]\2", text)
    text = _EMAIL.sub("[REDACTED-EMAIL]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return text
