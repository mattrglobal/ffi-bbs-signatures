import unittest
from typing import List

from ursa_bbs_signatures import BlsKeyPair, IndexedMessage, CreateBlindedCommitmentRequest, blind_sign, \
    BlindSignRequest, create_blinded_commitment, unblind_signature, UnblindSignatureRequest


class TestApiBlindSign(unittest.TestCase):
    def test_sign_single_message(self):
        bls_key = BlsKeyPair.generate_g2()
        public_key = bls_key.get_bbs_key(2)

        messages: List[IndexedMessage] = [
            IndexedMessage('message_0', 0),
            IndexedMessage('message_1', 1)
        ]

        nonce = b'12345'

        commitment = create_blinded_commitment(CreateBlindedCommitmentRequest(public_key, messages, nonce))
        blind_signature = blind_sign(BlindSignRequest(bls_key, public_key, commitment.commitment, messages))

        self.assertIsNotNone(blind_signature)

    def test_unblind_message(self):
        bls_key = BlsKeyPair.generate_g2()
        public_key = bls_key.get_bbs_key(2)

        messages: List[IndexedMessage] = [
            IndexedMessage('message_0', 0),
            IndexedMessage('message_1', 1)
        ]

        nonce = b'12345'

        commitment = create_blinded_commitment(CreateBlindedCommitmentRequest(public_key, messages, nonce))
        blind_signature = blind_sign(BlindSignRequest(bls_key, public_key, commitment.commitment, messages))

        result = unblind_signature(UnblindSignatureRequest(
            blind_signature,
            commitment.blinding_factor
        ))

        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
