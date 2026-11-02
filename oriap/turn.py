"""Identifiants TURN éphémères (mode `use-auth-secret` de coturn / TURN REST API)."""
import base64
import hashlib
import hmac
import time


def turn_credentials(secret: str, ttl: int = 3600, now: float | None = None) -> tuple[str, str]:
    username = str(int((now if now is not None else time.time()) + ttl))
    digest = hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    return username, base64.b64encode(digest).decode()
