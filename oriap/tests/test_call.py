import asyncio
import unittest

import numpy as np

from oriap import Identity
from oriap.audio import ToneTrack
from oriap.node import OriaNode
from oriap.signaling import serve


class CallTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = await serve("127.0.0.1", 0).__aenter__()
        self.url = f"ws://127.0.0.1:{self.srv.sockets[0].getsockname()[1]}"

    async def asyncTearDown(self):
        self.srv.close()
        await self.srv.wait_closed()

    async def test_call_by_id_audio_flows(self):
        got = asyncio.get_running_loop().create_future()

        def on_track(peer, track):
            async def pull():
                frames = [await track.recv() for _ in range(30)]
                got.set_result((peer, frames))
            asyncio.ensure_future(pull())

        a, b = Identity.generate(), Identity.generate()
        na = OriaNode(a, self.url, local_track=ToneTrack(440))
        nb = OriaNode(b, self.url, on_track=on_track, local_track=ToneTrack(880))
        await na.start()
        await nb.start()
        try:
            pc = await na.call(b.id)
            peer, frames = await asyncio.wait_for(got, 20)
            self.assertEqual(peer, a.id)  # B sait avec certitude que l'appelant est A
            self.assertEqual(na._sessions[b.id].hs.peer_id, b.id)
            # le flux reçu par B est bien la sinusoïde de A (pas du silence)
            self.assertGreater(max(np.abs(f.to_ndarray()).max() for f in frames), 3000)
            self.assertEqual(pc.connectionState in ("connecting", "connected"), True)
        finally:
            await na.stop()
            await nb.stop()

    async def test_offline_peer_times_out(self):
        a = Identity.generate()
        na = OriaNode(a, self.url)
        await na.start()
        try:
            with self.assertRaises(asyncio.TimeoutError):
                await na.call(Identity.generate().id, timeout=1)
        finally:
            await na.stop()

    async def test_signaling_rejects_impersonation(self):
        import json, websockets
        victim = Identity.generate()
        ws = await websockets.connect(self.url)
        await ws.recv()
        await ws.send(json.dumps({"type": "hello", "id": victim.id, "sig": Identity.generate().sign(b"x").hex()}))
        with self.assertRaises(websockets.ConnectionClosed):
            await ws.recv()


class IceConfigTest(unittest.TestCase):
    def test_default_has_no_servers(self):
        from oriap.node import ice_config
        self.assertEqual(ice_config([]).iceServers, [])

    def test_stun_and_turn_parsed(self):
        from oriap.node import ice_config
        cfg = ice_config([{"urls": "stun:s:3478"},
                          {"urls": "turn:t:3478", "username": "u", "credential": "c"}])
        self.assertEqual(cfg.iceServers[0].urls, "stun:s:3478")
        self.assertEqual((cfg.iceServers[1].username, cfg.iceServers[1].credential), ("u", "c"))

    def test_env_var(self):
        import os
        from unittest import mock
        from oriap.node import ice_config
        with mock.patch.dict(os.environ, {"ORIA_ICE_SERVERS": '[{"urls":"stun:e:1"}]'}):
            self.assertEqual(ice_config().iceServers[0].urls, "stun:e:1")


class RingAndTurnTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = await serve("127.0.0.1", 0, turn_secret="s3cret", turn_urls=["turn:t:3478"]).__aenter__()
        self.url = f"ws://127.0.0.1:{self.srv.sockets[0].getsockname()[1]}"

    async def asyncTearDown(self):
        self.srv.close()
        await self.srv.wait_closed()

    async def test_decline_then_accept_then_hangup(self):
        from oriap.node import CallDeclined
        decisions = iter([False, True])
        hung = asyncio.get_running_loop().create_future()
        a, b = Identity.generate(), Identity.generate()
        na = OriaNode(a, self.url, local_track=ToneTrack())
        nb = OriaNode(b, self.url, local_track=ToneTrack(), on_incoming=lambda peer: next(decisions),
                      on_hangup=lambda peer: hung.set_result(peer))
        await na.start(); await nb.start()
        try:
            with self.assertRaises(CallDeclined):
                await na.call(b.id)
            pc = await na.call(b.id)                    # 2e tentative : acceptée, même session
            self.assertIn(pc.connectionState, ("new", "connecting", "connected"))
            await na.hangup(b.id)
            self.assertEqual(await asyncio.wait_for(hung, 5), a.id)
        finally:
            await na.stop(); await nb.stop()

    async def test_server_gives_ephemeral_turn_credentials(self):
        from oriap.turn import turn_credentials
        n = OriaNode(Identity.generate(), self.url)
        await n.start()
        try:
            srv = n.rtc_config.iceServers[0]
            self.assertEqual(srv.urls, "turn:t:3478")
            self.assertEqual(srv.credential, turn_credentials("s3cret", now=int(srv.username) - 3600)[1])
        finally:
            await n.stop()

    def test_turn_credentials_known_value(self):
        from oriap.turn import turn_credentials
        u, c = turn_credentials("secret", 100, now=1000)
        self.assertEqual(u, "1100")
        import base64, hashlib, hmac
        self.assertEqual(c, base64.b64encode(hmac.new(b"secret", b"1100", hashlib.sha1).digest()).decode())


class GroupCallTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = await serve("127.0.0.1", 0).__aenter__()
        self.url = f"ws://127.0.0.1:{self.srv.sockets[0].getsockname()[1]}"
        self.heard = {}

    async def asyncTearDown(self):
        self.srv.close()
        await self.srv.wait_closed()

    def make(self, name, freq, **kw):
        ident = Identity.generate()

        def on_track(peer, track):
            async def pull():
                frames = [await track.recv() for _ in range(40)]
                x = np.concatenate([f.to_ndarray().reshape(-1)[0::2] for f in frames[10:]]).astype(float)
                spec = np.abs(np.fft.rfft(x * np.hanning(len(x))))
                self.heard[(name, peer)] = (np.argmax(spec[1:]) + 1) * 48000 / len(x)
            asyncio.ensure_future(pull())
        return ident, OriaNode(ident, self.url, local_track=ToneTrack(freq), on_track=on_track, **kw)

    async def test_three_way_mesh(self):
        (ia, a), (ib, b), (ic, c) = self.make("A", 440), self.make("B", 660), self.make("C", 880)
        for n in (a, b, c):
            await n.start()
        try:
            res = await a.call_group([ib.id, ic.id])
            self.assertTrue(all(not isinstance(r, Exception) for r in res.values()), res)
            deadline = asyncio.get_running_loop().time() + 25
            while len(self.heard) < 6 and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.1)
            ids = {ia.id: ("A", 440), ib.id: ("B", 660), ic.id: ("C", 880)}
            self.assertEqual(len(self.heard), 6)            # chacun entend les deux autres
            for (listener, speaker_id), freq in self.heard.items():
                self.assertNotEqual(ids[speaker_id][0], listener)
                self.assertAlmostEqual(freq, ids[speaker_id][1], delta=15)   # et reconnaît chaque voix
        finally:
            for n in (a, b, c):
                await n.stop()

    async def test_one_decline_does_not_break_others(self):
        from oriap.node import CallDeclined
        (ia, a), (ib, b), (ic, c) = self.make("A", 440), self.make("B", 660), self.make("C", 880, on_incoming=lambda p: False)
        for n in (a, b, c):
            await n.start()
        try:
            res = await a.call_group([ib.id, ic.id])
            self.assertIsInstance(res[ic.id], CallDeclined)
            self.assertFalse(isinstance(res[ib.id], Exception))
            for _ in range(150):
                if len(self.heard) >= 2:
                    break
                await asyncio.sleep(0.1)
            self.assertEqual({k for k in self.heard}, {("A", ib.id), ("B", ia.id)})   # A et B s'entendent, C exclu
        finally:
            for n in (a, b, c):
                await n.stop()


if __name__ == "__main__":
    unittest.main()
