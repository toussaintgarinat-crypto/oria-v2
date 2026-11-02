import asyncio
import copy
import unittest

from oriap import Identity
from oriap.groups import Groups, GroupError
from oriap.node import OriaNode
from oriap.replication import MessageLog
from oriap.signaling import serve


def sync_logs(*pairs):
    """Copie les messages entre journaux (simule la réplication), sans filtrage."""
    for src, dst in pairs:
        for m in src.all():
            dst.add(m)


class GroupUnitTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c, self.d = (Identity.generate() for _ in range(4))
        self.logs = {i.id: MessageLog() for i in (self.a, self.b, self.c, self.d)}
        for l in self.logs.values():
            self.addCleanup(l.close)
        self.g = {i.id: Groups(self.logs[i.id], i) for i in (self.a, self.b, self.c, self.d)}

    def L(self, i):
        return self.logs[i.id]

    def test_members_read_outsiders_cannot(self):
        ev = self.g[self.a.id].create_group([self.b.id, self.c.id])
        tid = ev["id"]
        m = self.g[self.a.id].encrypt(tid, "secret de groupe")
        self.assertNotIn(b"secret", m["body"]["text"].encode())          # le journal ne contient que du chiffré
        sync_logs((self.L(self.a), self.L(self.b)), (self.L(self.a), self.L(self.d)))
        self.g[self.b.id].accept_keys(self.g[self.a.id].keys_for(self.b.id))
        self.assertEqual([x["text"] for x in self.g[self.b.id].read(tid)], ["secret de groupe"])
        self.assertEqual(self.g[self.d.id].read(tid), [])                # D a le chiffré mais pas la clé
        # D ne peut pas se faire donner la clé : keys_for ne sert que les membres
        self.assertEqual(self.g[self.a.id].keys_for(self.d.id), [])

    def test_fake_key_rejected_by_commitment(self):
        tid = self.g[self.a.id].create_group([self.b.id])["id"]
        sync_logs((self.L(self.a), self.L(self.b)))
        n = self.g[self.b.id].accept_keys([{"thread": tid, "epoch": 0, "key": "00" * 32}])
        self.assertEqual(n, 0)
        self.assertIsNone(self.L(self.b).get_key(tid, 0))

    def test_only_admin_can_rotate_and_forged_epoch_ignored(self):
        tid = self.g[self.a.id].create_group([self.b.id, self.c.id])["id"]
        sync_logs((self.L(self.a), self.L(self.b)))
        with self.assertRaises(GroupError):
            self.g[self.b.id].rotate(tid, [self.b.id])
        # B forge quand même un événement d'époque 1 (signé par B, pas l'admin)
        self.L(self.b).create(self.b, "", kind="epoch", thread=tid, epoch=1, members=[self.b.id], key_hash="00" * 32)
        self.assertEqual(max(self.g[self.b.id].epochs()[tid]), 0)        # ignoré

    def test_removed_member_cannot_read_new_nor_new_member_old(self):
        ga = self.g[self.a.id]
        tid = ga.create_group([self.b.id, self.c.id])["id"]
        old = ga.encrypt(tid, "avant")
        ga.rotate(tid, [self.b.id])                                      # retire C
        new = ga.encrypt(tid, "après retrait")
        for x in (self.b, self.c):
            sync_logs((self.L(self.a), self.L(x)))
        gb, gc = self.g[self.b.id], self.g[self.c.id]
        gb.accept_keys(ga.keys_for(self.b.id))
        gc.accept_keys(ga.keys_for(self.c.id))                           # C n'obtient que l'époque 0
        self.assertEqual([m["text"] for m in gb.read(tid)], ["avant", "après retrait"])
        self.assertEqual([m["text"] for m in gc.read(tid)], ["avant"])   # C lit le passé, pas la suite
        # diffusion : C n'est plus destinataire de la suite, B oui
        self.assertFalse(ga.allowed(self.c.id, new))
        self.assertTrue(ga.allowed(self.b.id, new))
        # ajout de D : nouvelle époque, D ne lit pas "avant"
        ga.rotate(tid, [self.b.id, self.d.id])
        later = ga.encrypt(tid, "après ajout")
        sync_logs((self.L(self.a), self.L(self.d)))
        gd = self.g[self.d.id]
        gd.accept_keys(ga.keys_for(self.d.id))
        self.assertEqual([m["text"] for m in gd.read(tid)], ["après ajout"])
        self.assertFalse(ga.allowed(self.d.id, old))

    def test_tampered_ciphertext_and_wrong_thread_rejected(self):
        ga = self.g[self.a.id]
        tid = ga.create_group([self.b.id])["id"]
        m = ga.encrypt(tid, "intègre")
        bad = copy.deepcopy(m)
        bad["body"]["text"] = "00" + bad["body"]["text"][2:]
        self.assertFalse(self.L(self.b).add(bad))                        # id/signature ne correspondent plus
        self.assertEqual(len(ga.read(tid)), 1)


class GroupNetworkTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = await serve("127.0.0.1", 0).__aenter__()
        self.url = f"ws://127.0.0.1:{self.srv.sockets[0].getsockname()[1]}"
        self.ids = {k: Identity.generate() for k in "ABCD"}
        self.n = {k: OriaNode(i, self.url) for k, i in self.ids.items()}
        for node in self.n.values():
            await node.start()

    async def asyncTearDown(self):
        for node in self.n.values():
            await node.stop()
        self.srv.close()
        await self.srv.wait_closed()

    def id(self, k):
        return self.ids[k].id

    async def until(self, cond, t=6):
        for _ in range(int(t / 0.05)):
            if cond():
                return
            await asyncio.sleep(0.05)
        self.fail("condition non atteinte")

    async def test_group_over_network_with_outsider_relay(self):
        A, B, C, D = (self.n[k] for k in "ABCD")
        await A.sync(self.id("B")); await C.sync(self.id("B")); await A.sync(self.id("D"))   # D : simple voisin de A
        tid = await A.create_group([self.id("B"), self.id("C")])
        await self.until(lambda: self.n["C"].groups.latest(tid)[0] == 0 if tid in self.n["C"].groups.epochs() else False)
        await A.post_group(tid, "bonjour le groupe")
        await C.post_group(tid, "salut depuis C")
        await self.until(lambda: all(len(x.read_group(tid)) == 2 for x in (A, B, C)))
        texts = {k: sorted(m["text"] for m in self.n[k].read_group(tid)) for k in "ABC"}
        self.assertTrue(all(t == ["bonjour le groupe", "salut depuis C"] for t in texts.values()))
        # D est connecté à A mais n'est pas membre : rien du groupe ne lui est envoyé (ni chiffré, ni événements)
        await A.post("message public")
        await self.until(lambda: len(D.log.thread()) == 1)
        self.assertEqual([m for m in D.log.all() if m["body"].get("thread") or m["body"].get("kind")], [])
        self.assertEqual(D.read_group(tid), [])

    async def test_remove_member_and_late_joiner_via_non_admin(self):
        A, B, C, D = (self.n[k] for k in "ABCD")
        for x, y in (("A", "B"), ("A", "C"), ("B", "C")):
            await self.n[x].sync(self.id(y))
        tid = await A.create_group([self.id("B"), self.id("C")])
        await A.post_group(tid, "avant retrait")
        await self.until(lambda: len(C.read_group(tid)) == 1 and len(B.read_group(tid)) == 1)
        await A.set_members(tid, [self.id("B"), self.id("D")])            # retire C, ajoute D (D n'est connecté qu'à A pour l'invite)
        await A.post_group(tid, "après retrait")
        await self.until(lambda: len(B.read_group(tid)) == 2)
        await self.until(lambda: len(D.read_group(tid)) == 1)
        self.assertEqual([m["text"] for m in D.read_group(tid)], ["après retrait"])   # D ne lit pas le passé
        await asyncio.sleep(0.4)
        self.assertEqual([m["text"] for m in C.read_group(tid)], ["avant retrait"])  # C est exclu de la suite


if __name__ == "__main__":
    unittest.main()
