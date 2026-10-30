import unittest
from oriap import Identity, Handshake, HandshakeError, id_to_pubkey


def run(a_hs, b_hs):
    h1 = a_hs.start()
    h2 = b_hs.handle_hello1(h1)
    auth = a_hs.handle_hello2(h2)
    b_hs.handle_auth(auth)


class T(unittest.TestCase):
    def setUp(self):
        self.a, self.b = Identity.generate(), Identity.generate()

    def test_id_roundtrip(self):
        self.assertEqual(id_to_pubkey(self.a.id), self.a.public_bytes)
        self.assertEqual(Identity.from_seed(self.a.seed()).id, self.a.id)

    def test_mutual_auth_and_channel(self):
        A, B = Handshake(self.a, self.b.id), Handshake(self.b)
        run(A, B)
        self.assertEqual(A.peer_id, self.b.id)
        self.assertEqual(B.peer_id, self.a.id)
        self.assertEqual(B.channel.decrypt(A.channel.encrypt(b"salut")), b"salut")
        self.assertEqual(A.channel.decrypt(B.channel.encrypt(b"yo")), b"yo")

    def test_replay_rejected(self):
        A, B = Handshake(self.a), Handshake(self.b)
        run(A, B)
        f = A.channel.encrypt(b"x")
        B.channel.decrypt(f)
        with self.assertRaises(ValueError):
            B.channel.decrypt(f)

    def test_wrong_peer_rejected(self):
        A, B = Handshake(self.a, Identity.generate().id), Handshake(self.b)
        with self.assertRaises(HandshakeError):
            run(A, B)

    def test_tampered_hello2_rejected(self):
        A, B = Handshake(self.a), Handshake(self.b)
        h2 = B.handle_hello1(A.start())
        h2["eph"] = "00" * 32
        with self.assertRaises(HandshakeError):
            A.handle_hello2(h2)

    def test_impersonation_rejected(self):
        # M prétend être A mais signe avec sa propre clé
        m = Identity.generate()
        A, B = Handshake(self.a), Handshake(self.b)
        h1 = A.start()
        h2 = B.handle_hello1(h1)
        bad = Handshake(m)
        bad._h1, bad._h2 = h1, B._h2
        with self.assertRaises(HandshakeError):
            B.handle_auth(bad_sig := {"sig": m.sign(b"nimporte quoi").hex()})


if __name__ == "__main__":
    unittest.main()
