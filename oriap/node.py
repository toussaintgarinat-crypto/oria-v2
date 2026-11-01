"""Nœud Oria : se connecte à la signalisation, fait le handshake OriaP avec un pair,
puis échange l'offre/réponse WebRTC chiffrées (le serveur ne voit pas le SDP).
Le SDP contient l'empreinte DTLS : elle est donc liée aux ID Oria authentifiés."""
import asyncio
import json
import os
from typing import Awaitable, Callable

import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription

from .handshake import Handshake
from .identity import Identity
from .signaling import CTX



def ice_config(servers: list[dict] | None = None) -> RTCConfiguration:
    """Configuration ICE. `servers` = [{"urls": "stun:h:3478"}, {"urls": "turn:h:3478", "username": u, "credential": c}].
    À défaut, variable d'environnement ORIA_ICE_SERVERS (JSON) ; sinon aucun serveur (LAN/loopback)."""
    if servers is None:
        servers = json.loads(os.environ.get("ORIA_ICE_SERVERS", "[]"))
    return RTCConfiguration(iceServers=[
        RTCIceServer(urls=s["urls"], username=s.get("username"), credential=s.get("credential")) for s in servers
    ])


class Session:
    def __init__(self, hs: Handshake):
        self.hs = hs
        self.hello2: asyncio.Future = asyncio.get_running_loop().create_future()
        self.ready = asyncio.Event()
        self.answer: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pc: RTCPeerConnection | None = None


class OriaNode:
    def __init__(self, identity: Identity, url: str, on_track: Callable | None = None, local_track=None,
                 ice_servers: list[dict] | None = None):
        self.identity, self.url = identity, url
        self.on_track = on_track          # appelé (peer_id, track) à la réception d'un flux
        self.local_track = local_track    # piste envoyée quand on décroche
        self.rtc_config = ice_config(ice_servers)
        self._ws = None
        self._sessions: dict[str, Session] = {}
        self._task: asyncio.Task | None = None

    async def start(self):
        self._ws = await websockets.connect(self.url)
        ch = json.loads(await self._ws.recv())
        sig = self.identity.sign(CTX + bytes.fromhex(ch["nonce"])).hex()
        await self._ws.send(json.dumps({"type": "hello", "id": self.identity.id, "sig": sig}))
        if json.loads(await self._ws.recv()).get("type") != "ready":
            raise ConnectionError("signalisation: auth refusée")
        self._task = asyncio.create_task(self._reader())

    async def stop(self):
        if self._task:
            self._task.cancel()
        for s in self._sessions.values():
            if s.pc:
                await s.pc.close()
        if self._ws:
            await self._ws.close()

    async def _send(self, to: str, payload: dict):
        await self._ws.send(json.dumps({"type": "relay", "to": to, "payload": payload}))

    async def _send_enc(self, peer: str, obj: dict):
        frame = self._sessions[peer].hs.channel.encrypt(json.dumps(obj).encode())
        await self._send(peer, {"t": "enc", "frame": frame.hex()})

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
            obj = json.loads(s.hs.channel.decrypt(bytes.fromhex(p["frame"])))
            if obj["kind"] == "offer":
                pc = self._new_pc(peer)
                await pc.setRemoteDescription(RTCSessionDescription(obj["sdp"], "offer"))
                await pc.setLocalDescription(await pc.createAnswer())
                await self._send_enc(peer, {"kind": "answer", "sdp": pc.localDescription.sdp})
            elif obj["kind"] == "answer":
                s.answer.set_result(obj["sdp"])

    async def call(self, peer_id: str, timeout: float = 15) -> RTCPeerConnection:
        """Appelle un ID Oria : handshake authentifié puis négociation WebRTC chiffrée."""
        s = self._sessions[peer_id] = Session(Handshake(self.identity, expected_peer=peer_id))
        await self._send(peer_id, {"t": "hs1", "m": s.hs.start()})
        auth = s.hs.handle_hello2(await asyncio.wait_for(s.hello2, timeout))
        await self._send(peer_id, {"t": "auth", "m": auth})
        pc = self._new_pc(peer_id)
        await pc.setLocalDescription(await pc.createOffer())
        await self._send_enc(peer_id, {"kind": "offer", "sdp": pc.localDescription.sdp})
        await pc.setRemoteDescription(RTCSessionDescription(await asyncio.wait_for(s.answer, timeout), "answer"))
        return pc
