"""Handshake mutuel en 3 messages, sans tiers de confiance.

A -> B  hello1 {v, id, eph, nonce}
B -> A  hello2 {v, id, eph, nonce, sig}   sig_B = Sign_B(CTX || hello1 || hello2_sans_sig)
A -> B  auth   {sig}                      sig_A = Sign_A(CTX || hello1 || hello2_sans_sig || "A")
Clé de session : HKDF(X25519(eph_a, eph_b), salt=nonce_a||nonce_b).
"""
import json
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .channel import SecureChannel
from .identity import Identity

VERSION = 1
CTX = b"oriap/v1/handshake"
MAX_SKEW = 120  # secondes


class HandshakeError(Exception):
    pass


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


class Handshake:
    def __init__(self, identity: Identity, expected_peer: str | None = None):
        self.identity = identity
        self.expected_peer = expected_peer
        self._eph = X25519PrivateKey.generate()
        self._nonce = os.urandom(16)
        self._h1: dict | None = None
        self._h2: dict | None = None
        self.peer_id: str | None = None
        self.channel: SecureChannel | None = None
        self._initiator = False

    def _hello(self) -> dict:
        return {"v": VERSION, "id": self.identity.id, "eph": _raw(self._eph.public_key()).hex(),
                "nonce": self._nonce.hex(), "ts": int(time.time())}

    def _check_hello(self, h: dict) -> None:
        if h.get("v") != VERSION:
            raise HandshakeError("version non supportée")
        if abs(time.time() - h.get("ts", 0)) > MAX_SKEW:
            raise HandshakeError("horodatage hors tolérance")
        if self.expected_peer and h.get("id") != self.expected_peer:
            raise HandshakeError("ID inattendu")

    def _finish(self, peer_eph_hex: str, nonce_a: str, nonce_b: str) -> None:
        shared = self._eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_eph_hex)))
        key = HKDF(hashes.SHA256(), 64, bytes.fromhex(nonce_a) + bytes.fromhex(nonce_b), b"oriap/v1/session").derive(shared)
        k_ab, k_ba = key[:32], key[32:]
        self.channel = SecureChannel(k_ab, k_ba) if self._initiator else SecureChannel(k_ba, k_ab)

    # --- initiateur (A) ---
    def start(self) -> dict:
        self._initiator = True
        self._h1 = self._hello()
        return self._h1

    def handle_hello2(self, h2: dict) -> dict:
        body = {k: v for k, v in h2.items() if k != "sig"}
        self._check_hello(body)
        if not Identity.verify(body["id"], bytes.fromhex(h2["sig"]), CTX + _canon(self._h1) + _canon(body)):
            raise HandshakeError("signature de B invalide")
        self._h2, self.peer_id = body, body["id"]
        self._finish(body["eph"], self._h1["nonce"], body["nonce"])
        return {"sig": self.identity.sign(CTX + _canon(self._h1) + _canon(body) + b"A").hex()}

    # --- répondeur (B) ---
    def handle_hello1(self, h1: dict) -> dict:
        self._check_hello(h1)
        self._h1 = h1
        body = self._hello()
        self._h2 = body
        sig = self.identity.sign(CTX + _canon(h1) + _canon(body)).hex()
        return {**body, "sig": sig}

    def handle_auth(self, msg: dict) -> None:
        h1, h2 = self._h1, self._h2
        if not Identity.verify(h1["id"], bytes.fromhex(msg["sig"]), CTX + _canon(h1) + _canon(h2) + b"A"):
            raise HandshakeError("signature de A invalide")
        self.peer_id = h1["id"]
        self._finish(h1["eph"], h1["nonce"], h2["nonce"])
