"""Serveur de signalisation WebSocket : annuaire d'ID en ligne + relais opaque.

Le serveur n'est pas de confiance : il authentifie seulement la possession de la clé
(challenge signé) pour empêcher l'usurpation d'adresse, et relaie des charges utiles
qu'il ne comprend pas. L'authentification de bout en bout reste faite par le handshake OriaP.
"""
import json
import os

import websockets

from .identity import Identity

CTX = b"oriap/v1/signal"


async def _handler(ws, registry: dict):
    nonce = os.urandom(16)
    await ws.send(json.dumps({"type": "challenge", "nonce": nonce.hex()}))
    try:
        hello = json.loads(await ws.recv())
        oria_id = hello["id"]
        if hello.get("type") != "hello" or not Identity.verify(oria_id, bytes.fromhex(hello["sig"]), CTX + nonce):
            await ws.close(4401, "auth")
            return
    except (KeyError, ValueError, websockets.ConnectionClosed):
        await ws.close(4400, "bad hello")
        return

    old = registry.get(oria_id)
    registry[oria_id] = ws
    if old is not None:
        await old.close(4409, "replaced")
    await ws.send(json.dumps({"type": "ready"}))
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
                if msg.get("type") != "relay":
                    continue
                target = registry.get(msg["to"])
            except (ValueError, KeyError, AttributeError):
                continue
            if target is None:
                await ws.send(json.dumps({"type": "error", "code": "offline", "to": msg["to"]}))
            else:
                await target.send(json.dumps({"type": "relay", "from": oria_id, "payload": msg.get("payload")}))
    except websockets.ConnectionClosed:
        pass
    finally:
        if registry.get(oria_id) is ws:
            del registry[oria_id]


def serve(host: str = "127.0.0.1", port: int = 8765):
    """Retourne le context manager websockets.serve (usage : `async with serve(...)`)."""
    registry: dict = {}

    async def handler(ws):
        await _handler(ws, registry)

    return websockets.serve(handler, host, port)
