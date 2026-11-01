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


if __name__ == "__main__":
    unittest.main()
