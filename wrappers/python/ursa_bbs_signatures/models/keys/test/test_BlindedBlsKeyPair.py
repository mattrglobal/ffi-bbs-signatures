import unittest

from ursa_bbs_signatures import BlindedBlsKeyPair


class TestBlindedBlsKeyPair(unittest.TestCase):
    def test_generate_g2_key_with_seed(self):
        seed = 'just a seed'
        key_pair = BlindedBlsKeyPair.generate_g2(seed)
        self.assertIsNotNone(key_pair, "Key pair should not be None")
        self.assertIsNotNone(key_pair.public_key, "Key pair should have public key")
        self.assertIsNotNone(key_pair.secret_key, "Key pair should have secret key")
        self.assertTrue(key_pair.is_g2, "Key should be G2 key")
        self.assertFalse(key_pair.is_g1, "Key should NOT be G1 key")

        self.assertEqual(BlindedBlsKeyPair.secret_key_size(), len(key_pair.secret_key))
        self.assertEqual(BlindedBlsKeyPair.public_g2_key_size(), len(key_pair.public_key))
        self.assertEqual(BlindedBlsKeyPair.blinding_factor_size(), len(key_pair.blinding_factor))

    def test_generate_g1_key_with_seed(self):
        seed = 'just a seed'
        key_pair = BlindedBlsKeyPair.generate_g1(seed)
        self.assertIsNotNone(key_pair, "Key pair should not be None")
        self.assertIsNotNone(key_pair.public_key, "Key pair should have public key")
        self.assertIsNotNone(key_pair.secret_key, "Key pair should have secret key")
        self.assertTrue(key_pair.is_g1, "Key should be G1 key")
        self.assertFalse(key_pair.is_g2, "Key should NOT be G2 key")

        self.assertEqual(BlindedBlsKeyPair.secret_key_size(), len(key_pair.secret_key))
        self.assertEqual(BlindedBlsKeyPair.public_g1_key_size(), len(key_pair.public_key))

        self.assertEqual(BlindedBlsKeyPair.blinding_factor_size(), len(key_pair.blinding_factor))

if __name__ == '__main__':
    unittest.main()
