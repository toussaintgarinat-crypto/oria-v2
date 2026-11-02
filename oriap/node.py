"""Nœud Oria : signalisation, handshake OriaP, appels WebRTC et réplication de messages.

Tout ce qui suit le handshake (SDP, sonnerie, synchronisation) circule chiffré sous la clé de
session ; le serveur de signalisation ne voit que des octets opaques. Le SDP contient l'empreinte
DTLS : elle est liée aux ID Oria authentifiés.
"""
import asyncio
import inspect
import json
import os
from typing import Callable

import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription

from .handshake import Handshake
from .identity import Identity
from .replication import MessageLog
from .signaling import CTX


def ice_config(servers: list[dict] | None = None) -> RTCConfiguration:
    """Configuration ICE. `servers` = [{"urls": "stun:h:3478"}, {"urls": "turn:h:3478", "username": u, "credential": c}].
    À défaut, variable d'environnement ORIA_ICE_SERVERS (JSON) ; sinon aucun serveur (LAN/loopback)."""
    if servers is None:
        servers = json.loads(os.environ.get("ORIA_ICE_SERVERS", "[]"))
    return RTCConfiguration(iceServers=[
        RTCIceServer(urls=s["urls"], username=s.get("username"), credential=s.get("credential")) for s in servers
    ])


class CallDeclined(Exception):
    pass


class Session:
    def __init__(self, hs: Handshake):
        loop = asyncio.get_running_loop()
        self.hs = hs
        self.hello2: asyncio.Future = loop.create_future()
        self.ready = asyncio.Event()
        self.reply: asyncio.Future = loop.create_future()   # accept / decline
        self.answer: asyncio.Future = loop.create_future()  # SDP
        self.pc: RTCPeerConnection | None = None


class OriaNode:
    def __init__(self, identity: Identity, url: str, on_track: Callable | None = None, local_track=None,
                 ice_servers: list[dict] | None = None, on_incoming: Callable | None = None,
                 on_hangup: Callable | None = None, log: MessageLog | None = None):
        self.identity, self.url = identity, url
        self.on_track = on_track          # (peer_id, track) à la réception d'un flux
        self.on_incoming = on_incoming    # (peer_id) -> bool | awaitable[bool] ; défaut : accepter
        self.on_hangup = on_hangup        # (peer_id)
        self.local_track = local_track    # piste envoyée quand on décroche / appelle
        self._own_log = log is None
        self.log = log if log is not None else MessageLog()
        self._ice_explicit = ice_servers is not None or bool(os.environ.get("ORIA_ICE_SERVERS"))
        self.rtc_config = ice_config(ice_servers)
        self._ws = None
        self._sessions: dict[str, Session] = {}
        self._task: asyncio.Task | None = None
        self._bg: set[asyncio.Task] = set()

    # --- connexion ---
    async def start(self):
        self._ws = await websockets.connect(self.url)
        ch = json.loads(await self._ws.recv())
        sig = self.identity.sign(CTX + bytes.fromhex(ch["nonce"])).hex()
        await self._ws.send(json.dumps({"type": "hello", "id": self.identity.id, "sig": sig}))
        ready = json.loads(await self._ws.recv())
        if ready.get("type") != "ready":
            raise ConnectionError("signalisation: auth refusée")
        if not self._ice_explicit and ready.get("ice_servers"):
            self.rtc_config = ice_config(ready["ice_servers"])  # identifiants TURN éphémères du serveur
        self._task = asyncio.create_task(self._reader())

    async def stop(self):
        if self._task:
            self._task.cancel()
        for t in list(self._bg):
            t.cancel()
        for s in self._sessions.values():
            if s.pc:
                await s.pc.close()
        if self._ws:
            await self._ws.close()
        if self._own_log:
            self.log.close()

    def _spawn(self, coro):
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    # --- transport ---
    async def _send(self, to: str, payload: dict):
        await self._ws.send(json.dumps({"type": "relay", "to": to, "payload": payload}))

    async def _send_enc(self, peer: str, obj: dict):
        frame = self._sessions[peer].hs.channel.encrypt(json.dumps(obj).encode())
        await self._send(peer, {"t": "enc", "frame": frame.hex()})

    async def _reader(self):
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                if msg.get("type") == "relay":
                    try:
                        await self._on_relay(msg["from"], msg["payload"])
                    except Exception:  # un pair défaillant ne doit pas tuer le nœud
                        self._sessions.pop(msg["from"], None)
        except (asyncio.CancelledError, websockets.ConnectionClosed):
            pass

    async def _on_relay(self, peer: str, p: dict):
        t = p["t"]
        if t == "hs1":
            s = self._sessions[peer] = Session(Handshake(self.identity))
            await self._send(peer, {"t": "hs2", "m": s.hs.handle_hello1(p["m"])})
        elif t == "hs2" and peer in self._sessions:
            self._sessions[peer].hello2.set_result(p["m"])
        elif t == "auth" and peer in self._sessions:
            s = self._sessions[peer]
            s.hs.handle_auth(p["m"])
            s.ready.set()
        elif t == "enc" and peer in self._sessions:
            s = self._sessions[peer]
            await self._on_app(peer, s, json.loads(s.hs.channel.decrypt(bytes.fromhex(p["frame"]))))

    async def _on_app(self, peer: str, s: Session, obj: dict):
        k = obj["kind"]
        if k == "offer":
            pc = self._new_pc(peer)
            await pc.setRemoteDescription(RTCSessionDescription(obj["sdp"], "offer"))
            await pc.setLocalDescription(await pc.createAnswer())
            await self._send_enc(peer, {"kind": "answer", "sdp": pc.localDescription.sdp})
        elif k == "answer":
            s.answer.set_result(obj["sdp"])
        elif k == "ring":
            self._spawn(self._answer_ring(peer))
        elif k in ("accept", "decline"):
            s.reply.set_result(k)
        elif k == "bye":
            if s.pc:
                await s.pc.close()
                s.pc = None
            if self.on_hangup:
                self.on_hangup(peer)
        elif k == "sync_have":      # le pair annonce ses ids : on renvoie ce qui lui manque + nos ids
            theirs = set(obj["ids"])
            await self._send_enc(peer, {"kind": "sync_reply", "msgs": self.log.get(self.log.ids() - theirs),
                                        "ids": sorted(self.log.ids())})
        elif k == "sync_reply":
            new = [m for m in obj["msgs"] if self.log.add(m)]
            await self._gossip(new, exclude=peer)
            missing = self.log.ids() - set(obj["ids"])
            await self._send_enc(peer, {"kind": "sync_msgs", "msgs": self.log.get(missing)})
        elif k == "sync_msgs":
            new = [m for m in obj["msgs"] if self.log.add(m)]
            await self._gossip(new, exclude=peer)

    # --- appels ---
    def _new_pc(self, peer: str) -> RTCPeerConnection:
        pc = RTCPeerConnection(self.rtc_config)
        self._sessions[peer].pc = pc
        if self.local_track is not None:
            pc.addTrack(self.local_track)

        @pc.on("track")
        def _(track):
            if self.on_track:
                self.on_track(peer, track)
        return pc

    async def _answer_ring(self, peer: str):
        ok = True
        if self.on_incoming:
            r = self.on_incoming(peer)
            ok = await r if inspect.isawaitable(r) else r
        await self._send_enc(peer, {"kind": "accept" if ok else "decline"})

    async def _session(self, peer: str, timeout: float) -> Session:
        s = self._sessions.get(peer)
        if s and s.ready.is_set():
            return s
        s = self._sessions[peer] = Session(Handshake(self.identity, expected_peer=peer))
        await self._send(peer, {"t": "hs1", "m": s.hs.start()})
        try:
            auth = s.hs.handle_hello2(await asyncio.wait_for(s.hello2, timeout))
        except Exception:
            self._sessions.pop(peer, None)
            raise
        await self._send(peer, {"t": "auth", "m": auth})
        s.ready.set()
        return s

    async def call(self, peer_id: str, timeout: float = 15, ring_timeout: float = 30) -> RTCPeerConnection:
        """Appelle un ID Oria : handshake, sonnerie, puis négociation WebRTC. Lève CallDeclined si refusé."""
        s = await self._session(peer_id, timeout)
        loop = asyncio.get_running_loop()
        s.reply, s.answer = loop.create_future(), loop.create_future()
        await self._send_enc(peer_id, {"kind": "ring"})
        if await asyncio.wait_for(s.reply, ring_timeout) == "decline":
            raise CallDeclined(peer_id)
        pc = self._new_pc(peer_id)
        await pc.setLocalDescription(await pc.createOffer())
        await self._send_enc(peer_id, {"kind": "offer", "sdp": pc.localDescription.sdp})
        await pc.setRemoteDescription(RTCSessionDescription(await asyncio.wait_for(s.answer, timeout), "answer"))
        return pc

    async def hangup(self, peer_id: str):
        s = self._sessions.get(peer_id)
        if s and s.ready.is_set():
            await self._send_enc(peer_id, {"kind": "bye"})
        if s and s.pc:
            await s.pc.close()
            s.pc = None

    # --- messages répliqués ---
    async def post(self, text: str) -> dict:
        msg = self.log.create(self.identity, text)
        await self._gossip([msg])
        return msg

    async def _gossip(self, msgs: list[dict], exclude: str | None = None):
        """Pousse les nouveaux messages aux pairs connectés (hors source) : relais de proche en proche."""
        if not msgs:
            return
        for peer, s in list(self._sessions.items()):
            if peer != exclude and s.ready.is_set():
                try:
                    await self._send_enc(peer, {"kind": "sync_msgs", "msgs": msgs})
                except Exception:
                    pass

    async def sync(self, peer_id: str, timeout: float = 15):
        """Réconcilie le journal avec un pair (rattrapage après une absence)."""
        await self._session(peer_id, timeout)
        await self._send_enc(peer_id, {"kind": "sync_have", "ids": sorted(self.log.ids())})
