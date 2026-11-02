"""Fil de messages répliqué : journal de messages signés, auto-vérifiables, fusion par union.

Un message = {author, ts, text, parents} + id (SHA-256 du corps canonique) + sig (Ed25519 de l'auteur).
Le fil est un ensemble de messages (CRDT « grow-only set ») : l'union est commutative, associative
et idempotente, donc des nœuds qui ont les mêmes messages affichent le même fil. L'ordre
d'affichage est un tri topologique (parents avant enfants), départagé par (ts, id).
"""
import hashlib
import heapq
import json
import sqlite3
import time

from .identity import Identity

CTX = b"oriap/v1/msg"


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _msg_id(body: dict) -> str:
    return hashlib.sha256(CTX + _canon(body)).hexdigest()


class MessageLog:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path)
        self._db.execute("CREATE TABLE IF NOT EXISTS msgs (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS keys (thread TEXT, epoch INTEGER, key BLOB, PRIMARY KEY (thread, epoch))")
        self._msgs: dict[str, dict] = {m["id"]: m for m in (json.loads(r[0]) for r in self._db.execute("SELECT data FROM msgs"))}

    def close(self):
        self._db.close()

    def all(self) -> list[dict]:
        return list(self._msgs.values())

    def put_key(self, thread: str, epoch: int, key: bytes):
        """Clés de groupe stockées en clair dans la base locale : la protection du disque est à la charge de l'appareil."""
        self._db.execute("INSERT OR REPLACE INTO keys VALUES (?, ?, ?)", (thread, epoch, key))
        self._db.commit()

    def get_key(self, thread: str, epoch: int) -> bytes | None:
        r = self._db.execute("SELECT key FROM keys WHERE thread=? AND epoch=?", (thread, epoch)).fetchone()
        return r[0] if r else None

    def ids(self) -> set[str]:
        return set(self._msgs)

    def get(self, ids) -> list[dict]:
        return [self._msgs[i] for i in ids if i in self._msgs]

    def heads(self) -> list[str]:
        parents = {p for m in self._msgs.values() for p in m["body"]["parents"]}
        return sorted(i for i in self._msgs if i not in parents)

    @staticmethod
    def verify(msg: dict) -> bool:
        try:
            body = msg["body"]
            return (_msg_id(body) == msg["id"]
                    and Identity.verify(body["author"], bytes.fromhex(msg["sig"]), msg["id"].encode())
                    and isinstance(body["text"], str) and isinstance(body["ts"], int)
                    and isinstance(body["parents"], list))
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def add(self, msg: dict) -> bool:
        """Ajoute un message vérifié. Retourne True s'il est nouveau (idempotent sinon)."""
        if not self.verify(msg) or msg["id"] in self._msgs:
            return False
        self._msgs[msg["id"]] = msg
        self._db.execute("INSERT INTO msgs VALUES (?, ?)", (msg["id"], json.dumps(msg)))
        self._db.commit()
        return True

    def create(self, identity: Identity, text: str, ts: int | None = None, **extra) -> dict:
        """`extra` : champs signés supplémentaires (fil chiffré : thread, epoch, nonce, kind…)."""
        body = {**extra, "author": identity.id, "ts": int(time.time()) if ts is None else ts,
                "text": text, "parents": self.heads()}
        mid = _msg_id(body)
        msg = {"id": mid, "body": body, "sig": identity.sign(mid.encode()).hex()}
        self.add(msg)
        return msg

    def thread(self, thread_id: str | None = None) -> list[dict]:
        """Ordre déterministe : tri topologique, départage (ts, id). Sans argument : le fil public
        (messages hors groupe) ; avec un id : les messages (chiffrés) de ce groupe."""
        pending = {i: {p for p in m["body"]["parents"] if p in self._msgs} for i, m in self._msgs.items()}
        children: dict[str, list[str]] = {}
        for i, ps in pending.items():
            for p in ps:
                children.setdefault(p, []).append(i)
        key = lambda i: (self._msgs[i]["body"]["ts"], i)
        heap = [key(i) for i, ps in pending.items() if not ps]
        heapq.heapify(heap)
        out = []
        while heap:
            _, i = heapq.heappop(heap)
            b = self._msgs[i]["body"]
            if b.get("thread") == thread_id and b.get("kind") != "epoch":
                out.append(self._msgs[i])
            for c in children.get(i, []):
                pending[c].discard(i)
                if not pending[c]:
                    heapq.heappush(heap, key(c))
        return out
