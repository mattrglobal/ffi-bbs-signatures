import unittest

from ursa_bbs_signatures import BlsKeyPair, create_blinded_commitment, CreateBlindedCommitmentRequest, IndexedMessage
from ursa_bbs_signatures._ffi.bindings.bbs_blind_commitment import bbs_blind_signature_size


class TestApiBlindCommitment(unittest.TestCase):
    def test_get_blind_signature_size(self):
        result = bbs_blind_signature_size()
        self.assertEqual(112, result)

    def test_blind_commitment_single_message(self):
        key = BlsKeyPair.generate_g2()
        public_key = key.get_bbs_key(1)

        commitment = create_blinded_commitment(
            CreateBlindedCommitmentRequest(
                public_key=public_key,
                messages=[IndexedMessage('message_0', 0)],
                nonce=b'1234'
            ))

        self.assertIsNotNone(commitment)
        self.assertIsNotNone(commitment.blinding_factor)
        self.assertIsNotNone(commitment.blind_sign_context)
        self.assertIsNotNone(commitment.commitment)

if __name__ == '__main__':
    unittest.main()
