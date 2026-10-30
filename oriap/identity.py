import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

PREFIX = "oria:"


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=").lower()


def id_to_pubkey(oria_id: str) -> bytes:
    if not oria_id.startswith(PREFIX):
        raise ValueError("ID Oria invalide")
    s = oria_id[len(PREFIX):].upper()
    raw = base64.b32decode(s + "=" * (-len(s) % 8))
    if len(raw) != 32:
        raise ValueError("ID Oria invalide")
    return raw


class Identity:
    """Paire de clés Ed25519. L'ID Oria est la clé publique encodée (pas de numéro)."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self.public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.id = PREFIX + _b32(self.public_bytes)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed(self) -> bytes:
        return self._sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    @staticmethod
    def verify(oria_id: str, signature: bytes, data: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        try:
            Ed25519PublicKey.from_public_bytes(id_to_pubkey(oria_id)).verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False
