import asyncio
import copy
import unittest

from oriap import Identity
from oriap.node import OriaNode
from oriap.replication import MessageLog
from oriap.signaling import serve


class LogTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b = Identity.generate(), Identity.generate()

    def test_tampered_rejected_duplicate_idempotent(self):
        log, src = MessageLog(), MessageLog()
        m = src.create(self.a, "salut")
        bad = copy.deepcopy(m)
        bad["body"]["text"] = "modifié"
        self.assertFalse(log.add(bad))
        forged = copy.deepcopy(m)
        forged["body"]["author"] = self.b.id          # fausse attribution
        self.assertFalse(log.add(forged))
        self.assertTrue(log.add(m))
        self.assertFalse(log.add(m))
        self.assertEqual(len(log.thread()), 1)

    def test_concurrent_writes_converge_same_order(self):
        l1, l2 = MessageLog(), MessageLog()
        base = l1.create(self.a, "base", ts=1)
        l2.add(base)
        m1 = l1.create(self.a, "de A", ts=5)       # écritures concurrentes
        m2 = l2.create(self.b, "de B", ts=5)
        for m in (m2,):
            l1.add(m)
        for m in (m1,):
            l2.add(m)
        self.assertEqual([m["id"] for m in l1.thread()], [m["id"] for m in l2.thread()])
        self.assertEqual(l1.thread()[0]["id"], base["id"])   # parents avant enfants
        self.assertEqual(len(l1.thread()), 3)

    def test_persistence(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "log.db")
        first = MessageLog(path)
        m = first.create(self.a, "durable")
        first.close()
        again = MessageLog(path)
        self.assertEqual(again.thread()[0]["id"], m["id"])
        again.close()


class ThreeNodesTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = await serve("127.0.0.1", 0).__aenter__()
        self.url = f"ws://127.0.0.1:{self.srv.sockets[0].getsockname()[1]}"
        self.ids = [Identity.generate() for _ in range(3)]
        self.nodes = [OriaNode(i, self.url) for i in self.ids]

    async def asyncTearDown(self):
        for n in self.nodes:
            await n.stop()
        self.srv.close()
        await self.srv.wait_closed()

    async def settle(self, cond, t=5):
        for _ in range(int(t / 0.05)):
            if cond():
                return
            await asyncio.sleep(0.05)
        self.fail("pas de convergence")

    def same(self):
        ids = [[m["id"] for m in n.log.thread()] for n in self.nodes]
        return ids[0] == ids[1] == ids[2] and len(ids[0]) > 0

    async def test_offline_node_catches_up_via_relay(self):
        a, b, c = self.nodes
        await a.start(); await b.start()               # C est hors ligne
        await a.sync(self.ids[1].id)                    # A–B connectés
        await a.post("écrit pendant l'absence de C")
        await self.settle(lambda: len(b.log.ids()) == 1)
        await c.start()                                 # C revient, ne parle qu'à B
        await c.sync(self.ids[1].id)
        await self.settle(lambda: len(c.log.ids()) == 1)
        self.assertEqual(c.log.thread()[0]["body"]["author"], self.ids[0].id)  # authentique, relayé par B

    async def test_line_topology_gossip_and_concurrent_writes(self):
        a, b, c = self.nodes
        for n in self.nodes:
            await n.start()
        await a.sync(self.ids[1].id)                    # A–B
        await c.sync(self.ids[1].id)                    # C–B ; A et C ne se parlent jamais
        await asyncio.gather(a.post("a1"), c.post("c1"), b.post("b1"))
        await self.settle(lambda: all(len(n.log.ids()) == 3 for n in self.nodes))
        await self.settle(self.same)

    async def test_relay_cannot_forge(self):
        a, b, c = self.nodes
        for n in self.nodes:
            await n.start()
        await b.sync(self.ids[2].id)
        m = a.log.create(self.ids[0], "vrai")
        forged = copy.deepcopy(m)
        forged["body"]["text"] = "faux, injecté par B"
        await b._send_enc(self.ids[2].id, {"kind": "sync_msgs", "msgs": [forged]})
        await asyncio.sleep(0.5)
        self.assertEqual(len(c.log.ids()), 0)


if __name__ == "__main__":
    unittest.main()
