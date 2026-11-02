"""Fils de groupe chiffrés avec contrôle d'accès.

- Un groupe est une suite d'**époques**. Chaque époque = un événement signé par l'admin (créateur) :
  {kind:"epoch", epoch:n, members:[…], key_hash:SHA-256(clé d'époque)}. L'id du groupe est l'id de
  l'événement d'époque 0. Tout changement de membres (ajout/retrait) ouvre une nouvelle époque avec
  une nouvelle clé : un membre retiré ne peut pas lire la suite ; un nouveau membre ne lit pas le passé.
- Un message de groupe est un message du journal dont `text` = ChaCha20-Poly1305(clé d'époque) ;
  thread/epoch/nonce sont signés avec lui. Les relais ne voient que le chiffré.
- Les clés circulent entre membres sur les canaux OriaP ; `key_hash` (signé par l'admin) empêche
  d'imposer une fausse clé.
- La diffusion est limitée : un nœud n'envoie les éléments d'un groupe qu'à ses membres.
"""
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .identity import Identity
from .replication import MessageLog


def _aad(tid: str, epoch: int, author: str) -> bytes:
    return f"{tid}|{epoch}|{author}".encode()


class GroupError(Exception):
    pass


class Groups:
    def __init__(self, log: MessageLog, identity: Identity):
        self.log, self.me = log, identity

    # --- lecture de l'état (recalculé depuis le journal : rien à synchroniser en plus) ---
    def epochs(self) -> dict[str, dict[int, dict]]:
        msgs = [m for m in self.log.all() if m["body"].get("kind") == "epoch"]
        out: dict[str, dict[int, dict]] = {
            m["id"]: {0: m} for m in msgs
            if m["body"].get("epoch") == 0 and "thread" not in m["body"] and self._well_formed(m)
        }
        for m in sorted(msgs, key=lambda m: m["id"]):       # équivoque de l'admin : l'id le plus petit gagne
            b = m["body"]
            tid, n = b.get("thread"), b.get("epoch")
            if tid in out and isinstance(n, int) and n > 0 and n not in out[tid] \
                    and b["author"] == out[tid][0]["body"]["author"] and self._well_formed(m):
                out[tid][n] = m
        for tid, evs in out.items():                        # préfixe contigu 0..k seulement
            k = 0
            while k + 1 in evs:
                k += 1
            out[tid] = {n: e for n, e in evs.items() if n <= k}
        return out

    @staticmethod
    def _well_formed(m) -> bool:
        b = m["body"]
        return (isinstance(b.get("members"), list) and b["author"] in b["members"]
                and isinstance(b.get("key_hash"), str) and isinstance(b.get("epoch"), int))

    def latest(self, tid: str):
        evs = self.epochs().get(tid)
        if not evs:
            raise GroupError("groupe inconnu")
        n = max(evs)
        return n, evs[n]

    def members(self, tid: str, epoch: int | None = None) -> set[str]:
        evs = self.epochs().get(tid, {})
        ev = evs.get(max(evs) if epoch is None else epoch) if evs else None
        return set(ev["body"]["members"]) if ev else set()

    # --- administration ---
    def create_group(self, members: list[str]) -> dict:
        key = os.urandom(32)
        msg = self.log.create(self.me, "", kind="epoch", epoch=0, members=sorted({self.me.id, *members}),
                              key_hash=hashlib.sha256(key).hexdigest(), nonce=os.urandom(8).hex())
        self.log.put_key(msg["id"], 0, key)
        return msg

    def rotate(self, tid: str, members: list[str]) -> dict:
        evs = self.epochs().get(tid)
        if not evs or evs[0]["body"]["author"] != self.me.id:
            raise GroupError("seul l'admin peut modifier les membres")
        n = max(evs) + 1
        key = os.urandom(32)
        msg = self.log.create(self.me, "", kind="epoch", thread=tid, epoch=n, members=sorted({self.me.id, *members}),
                              key_hash=hashlib.sha256(key).hexdigest())
        self.log.put_key(tid, n, key)
        return msg

    # --- messages ---
    def encrypt(self, tid: str, text: str) -> dict:
        n, ev = self.latest(tid)
        key = self.log.get_key(tid, n)
        if self.me.id not in ev["body"]["members"] or key is None:
            raise GroupError("pas membre de l'époque courante (ou clé absente)")
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, text.encode(), _aad(tid, n, self.me.id))
        return self.log.create(self.me, ct.hex(), thread=tid, epoch=n, nonce=nonce.hex())

    def read(self, tid: str) -> list[dict]:
        evs = self.epochs().get(tid, {})
        out = []
        for m in self.log.thread(tid):
            b = m["body"]
            n = b.get("epoch")
            if n not in evs or b["author"] not in evs[n]["body"]["members"]:
                continue                                    # auteur non membre de cette époque : ignoré
            key = self.log.get_key(tid, n)
            if key is None:
                continue
            try:
                text = ChaCha20Poly1305(key).decrypt(bytes.fromhex(b["nonce"]), bytes.fromhex(b["text"]),
                                                     _aad(tid, n, b["author"])).decode()
            except (InvalidTag, ValueError, KeyError):
                continue
            out.append({"id": m["id"], "author": b["author"], "ts": b["ts"], "epoch": n, "text": text})
        return out

    # --- diffusion contrôlée et clés ---
    def allowed(self, peer: str, msg: dict) -> bool:
        """Cet élément peut-il être communiqué à `peer` ? (public : oui ; groupe : membres seulement)"""
        b = msg["body"]
        evs_all = self.epochs()
        if b.get("kind") == "epoch":
            tid = msg["id"] if b["epoch"] == 0 and "thread" not in b else b.get("thread")
            evs = evs_all.get(tid)
            ev = evs.get(b["epoch"]) if evs else None
            if ev is None or ev["id"] != msg["id"]:
                return False        # événement non reconnu (pas de l'admin, équivoque, hors préfixe)
            return peer in ev["body"]["members"] or peer in evs[max(evs)]["body"]["members"]
        tid = b.get("thread")
        if tid is None:
            return True
        evs = evs_all.get(tid)
        return bool(evs) and b.get("epoch") in evs and peer in evs[b["epoch"]]["body"]["members"]

    def keys_for(self, peer: str) -> list[dict]:
        grants = []
        for tid, evs in self.epochs().items():
            for n, ev in evs.items():
                key = self.log.get_key(tid, n)
                if key is not None and peer in ev["body"]["members"]:
                    grants.append({"thread": tid, "epoch": n, "key": key.hex()})
        return grants

    def accept_keys(self, grants: list[dict]) -> int:
        """Retourne le nombre de clés *nouvelles* acceptées (vérifiées contre key_hash signé par l'admin)."""
        evs_all, accepted = self.epochs(), 0
        for g in grants:
            try:
                ev = evs_all[g["thread"]][g["epoch"]]
                key = bytes.fromhex(g["key"])
            except (KeyError, ValueError, TypeError):
                continue
            if self.me.id in ev["body"]["members"] and hashlib.sha256(key).hexdigest() == ev["body"]["key_hash"] \
                    and self.log.get_key(g["thread"], g["epoch"]) is None:
                self.log.put_key(g["thread"], g["epoch"], key)
                accepted += 1
        return accepted
