import unittest

from ursa_bbs_signatures import BlsKeyPair


class TestBlsKeyPair(unittest.TestCase):

    def test_get_secret_key_size(self):
        self.assertEqual(BlsKeyPair.secret_key_size(), 32, "Secret key should be of length 32")

    def test_get_public_g1_key_size(self):
        self.assertEqual(BlsKeyPair.public_g1_key_size(), 48, "G1 key should be of length 48")

    def test_get_public_g2_key_size(self):
        self.assertEqual(BlsKeyPair.public_g2_key_size(), 96, "G2 key should be of length 96")

    def test_generate_g2_key_with_seed(self):
        seed = 'just a seed'
        key_pair = BlsKeyPair.generate_g2(seed)
        self.assertIsNotNone(key_pair, "Key pair should not be None")
        self.assertIsNotNone(key_pair.public_key, "Key pair should have public key")
        self.assertIsNotNone(key_pair.secret_key, "Key pair should have secret key")
        self.assertTrue(key_pair.is_g2, "Key should be G2 key")
        self.assertFalse(key_pair.is_g1, "Key should NOT be G1 key")

        self.assertEqual(BlsKeyPair.secret_key_size(), len(key_pair.secret_key))
        self.assertEqual(BlsKeyPair.public_g2_key_size(), len(key_pair.public_key))

    def test_generate_g1_key_with_seed(self):
        seed = 'just a seed'
        key_pair = BlsKeyPair.generate_g1(seed)
        self.assertIsNotNone(key_pair, "Key pair should not be None")
        self.assertIsNotNone(key_pair.public_key, "Key pair should have public key")
        self.assertIsNotNone(key_pair.secret_key, "Key pair should have secret key")
        self.assertTrue(key_pair.is_g1, "Key should be G1 key")
        self.assertFalse(key_pair.is_g2, "Key should NOT be G2 key")

        self.assertEqual(BlsKeyPair.secret_key_size(), len(key_pair.secret_key))
        self.assertEqual(BlsKeyPair.public_g1_key_size(), len(key_pair.public_key))

        self.assertEqual(BlsKeyPair.secret_key_size(), len(key_pair.secret_key))
        self.assertEqual(BlsKeyPair.public_g1_key_size(), len(key_pair.public_key))

    def test_bbs_from_secret_key(self):
        secret_key = BlsKeyPair.generate_g2()
        public_key = secret_key.get_bbs_key(1)

        self.assertIsNotNone(public_key)
        self.assertEqual(196, len(public_key.public_key))

    def test_bbs_from_public_key(self):
        bls_key_pair = BlsKeyPair.generate_g2()
        bbs_key_pair = BlsKeyPair(bls_key_pair.public_key)

        self.assertIsNone(bbs_key_pair.secret_key)

        public_key = bbs_key_pair.get_bbs_key(1)

        self.assertIsNotNone(public_key)
        self.assertIsNotNone(bbs_key_pair.public_key)
        self.assertIsNone(bbs_key_pair.secret_key)

        self.assertEqual(196, len(public_key.public_key))
        self.assertEqual(32, len(bls_key_pair.secret_key))

if __name__ == '__main__':
    unittest.main()
