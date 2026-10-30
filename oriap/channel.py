import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class SecureChannel:
    """Canal chiffré/authentifié, compteur anti-rejeu strictement croissant."""

    def __init__(self, send_key: bytes, recv_key: bytes):
        self._send, self._recv = ChaCha20Poly1305(send_key), ChaCha20Poly1305(recv_key)
        self._n_send = 0
        self._n_recv = 0

    @staticmethod
    def _nonce(n: int) -> bytes:
        return b"\0" * 4 + struct.pack(">Q", n)

    def encrypt(self, plaintext: bytes) -> bytes:
        n = self._n_send
        self._n_send += 1
        return struct.pack(">Q", n) + self._send.encrypt(self._nonce(n), plaintext, None)

    def decrypt(self, frame: bytes) -> bytes:
        n = struct.unpack(">Q", frame[:8])[0]
        if n < self._n_recv:
            raise ValueError("rejeu détecté")
        pt = self._recv.decrypt(self._nonce(n), frame[8:], None)
        self._n_recv = n + 1
        return pt
