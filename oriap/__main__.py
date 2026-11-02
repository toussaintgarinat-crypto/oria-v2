"""CLI de démonstration : python -m oriap {id,serve,listen,call,chat}

  python -m oriap serve  --port 8765 [--turn-secret S --turn-url turn:IP:3478]   # ou ORIA_TURN_SECRET / ORIA_TURN_URLS
  python -m oriap listen --url ws://H:8765 --key a.key [--decline] [--out recu.wav]
  python -m oriap call   --url ws://H:8765 --key b.key --to oria:... [--seconds 5] [--out recu.wav]
  python -m oriap chat   --url ws://H:8765 --key a.key --db a.db [--peer oria:...]
"""
import argparse
import asyncio
import os
import sys

from .audio import ToneTrack
from .identity import Identity
from .node import CallDeclined, OriaNode
from .replication import MessageLog
from .signaling import serve


def load_identity(path: str) -> Identity:
    """Charge (ou crée, en 0600) la graine privée. La graine ne s'affiche jamais."""
    if os.path.exists(path):
        return Identity.from_seed(bytes.fromhex(open(path).read().strip()))
    ident = Identity.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(ident.seed().hex())
    return ident


def _recorder(out):
    if not out:
        return None, lambda peer, track: asyncio.ensure_future(_drain(track))
    from aiortc.contrib.media import MediaRecorder
    rec = MediaRecorder(out)

    def on_track(peer, track):
        rec.addTrack(track)
        asyncio.ensure_future(rec.start())
    return rec, on_track


async def _drain(track):
    try:
        while True:
            await track.recv()
    except Exception:
        pass


async def run(a):
    if a.cmd == "serve":
        a.turn_secret = a.turn_secret or os.environ.get("ORIA_TURN_SECRET")   # via l'env : invisible dans `ps`
        a.turn_url = a.turn_url or [u for u in os.environ.get("ORIA_TURN_URLS", "").split(",") if u]
    if a.cmd == "id":
        print(load_identity(a.key).id)
    elif a.cmd == "serve":
        async with serve(a.host, a.port, a.turn_secret, a.turn_url):
            print(f"signalisation sur ws://{a.host}:{a.port}", flush=True)
            await asyncio.Future()
    elif a.cmd == "listen":
        me = load_identity(a.key)
        rec, on_track = _recorder(a.out)
        node = OriaNode(me, a.url, on_track=on_track, local_track=ToneTrack(880),
                        on_incoming=lambda peer: (print(f"appel de {peer} -> {'refusé' if a.decline else 'accepté'}", flush=True),
                                                  not a.decline)[1],
                        on_hangup=lambda peer: print(f"{peer} a raccroché", flush=True))
        await node.start()
        print(f"en ligne : {me.id}", flush=True)
        await asyncio.Future()
    elif a.cmd == "call":
        me = load_identity(a.key)
        rec, on_track = _recorder(a.out)
        node = OriaNode(me, a.url, on_track=on_track, local_track=ToneTrack(440))
        await node.start()
        try:
            await node.call(a.to)
            print("appel établi", flush=True)
            await asyncio.sleep(a.seconds)
            await node.hangup(a.to)
        except CallDeclined:
            print("appel refusé", flush=True)
        finally:
            if rec:
                await rec.stop()
            await node.stop()
    elif a.cmd == "chat":
        me = load_identity(a.key)
        node = OriaNode(me, a.url, log=MessageLog(a.db))
        await node.start()
        print(f"en ligne : {me.id}\nTapez un message (Entrée) ; /sync ID pour rattraper un pair ; /fil pour afficher.", flush=True)
        if a.peer:
            await node.sync(a.peer)
        loop = asyncio.get_running_loop()
        while True:
            line = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
            if not line:
                continue
            if line.startswith("/sync "):
                await node.sync(line.split()[1])
            elif line == "/fil":
                for m in node.log.thread():
                    print(f"[{m['body']['author'][:14]}…] {m['body']['text']}")
            else:
                await node.post(line)


def main():
    p = argparse.ArgumentParser(prog="oriap")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8765)
    s.add_argument("--turn-secret"); s.add_argument("--turn-url", action="append")
    for name in ("id", "listen", "call", "chat"):
        q = sub.add_parser(name); q.add_argument("--key", required=True)
        if name != "id":
            q.add_argument("--url", required=True)
    sub.choices["listen"].add_argument("--decline", action="store_true"); sub.choices["listen"].add_argument("--out")
    c = sub.choices["call"]; c.add_argument("--to", required=True); c.add_argument("--seconds", type=float, default=5); c.add_argument("--out")
    h = sub.choices["chat"]; h.add_argument("--db", default=":memory:"); h.add_argument("--peer")
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
