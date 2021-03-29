import unittest

from ursa_bbs_signatures import BlsKeyPair, sign, SignRequest, VerifyRequest, verify


class TestApiVerify(unittest.TestCase):

    def setUp(self) -> None:
        self.public_bls_key_alice = b"\x86M\xc0cUPQ\xdb\xdblE\x87E\x832p8\xf5\xb9\xbeM\x05\xf1G\x9emHe\x99\xf0T\xbfn\x85\x18\xdb\x86'W\x1c\xe3\x8aG\x97S\x01\xda\xfe\x0e\x15)\x144I\xf9\xd0:\xcc\xdb\xc5\xc26\x10\xf9@\xaa\x18\xf5,6Es\xfd\xc7\xf1tcZ\x98\xfe\xd6\xcct\xbfk\xfb\x9f\xf1\xad)\x15\x88w\x80\xdd\xea"

        self.secret_bls_key_alice = b'\x06\xe7w\xf4\x90\x0e\xacK\xb7\x94l\x00/\xaaFD\x1c\xff\x9c\xad\xdcq\xed\xb6#%\x7fu\xc7\x8c\xfe\x9c'

        self.public_bls_key_bob = b'\x91\xc1\xe7\xf6\xf3h&\x97\xc8%\xe5\x18xy*W\xbcy\x0e{\x9f\xba\xde\xfe\x14\x14\xb9(K_6=\xe0\x80\xe92\xe4%\x13\x88\x86\xaf\x86\x00\xeb!\x95B\x04[\xaa\xeaU\x82\xbe\x9fts\x96\xe9\xaeG\xf1!K\xe1\xb8M+\x03\x18\xd6\xa2\xa1\xac\x1f\xa5}\x12z\x17QjU\x99\x12Q\xfb2\x03\x86\xc7O4\x9d7'

        self.secret_bls_key_bob = b'j\xf2\xf1abM\xd3\xa5Kumz6\xeaK\x1c\x03\xac\x97"(' \
                                  b'kR\xdd\x84#]\xea\x82\xfb\x86\xf1 '
        self.messages = [
            "message 1",
            "message 2",
            "message 3",
            "message 4",
            "message 5",
        ]

        self.invalid_messages = [
            "message 1",
            "message X",
            "message 3",
            "message X",
            "message 5",
        ]

        self.valid_signature = sign(
            SignRequest(
                BlsKeyPair(
                    self.public_bls_key_alice,
                    self.secret_bls_key_alice
                ),
                self.messages
            )
        )

        self.invalid_signature = sign(
            SignRequest(
                BlsKeyPair(
                    self.public_bls_key_alice,
                    self.secret_bls_key_bob
                ),
                self.messages
            )
        )

    def test_verify_success(self):
        verify_key = BlsKeyPair(self.public_bls_key_alice)
        request = VerifyRequest(verify_key, self.valid_signature, self.messages)
        result = verify(request)
        self.assertTrue(result, "Verification should be successful")

    def test_verify_invalid_signature(self):
        verify_key = BlsKeyPair(self.public_bls_key_alice)
        request = VerifyRequest(verify_key, self.invalid_signature, self.messages)
        result = verify(request)
        self.assertFalse(result, "Verification should fail due to invalid signature")

    def test_verify_invalid_public_key(self):
        verify_key = BlsKeyPair(self.public_bls_key_bob)
        request = VerifyRequest(verify_key, self.valid_signature, self.messages)
        result = verify(request)
        self.assertFalse(result, "Verification should fail due to invalid public key")

    def test_verify_invalid_messages(self):
        verify_key = BlsKeyPair(self.public_bls_key_alice)
        request = VerifyRequest(verify_key, self.valid_signature, self.invalid_messages)
        result = verify(request)
        self.assertFalse(result,
                         "Verification should fail because verification messages differ from the "
                         "messages that were signed.")

    def test_verify_invalid_number_of_messages(self):
        verify_key = BlsKeyPair(self.public_bls_key_alice)
        request = VerifyRequest(verify_key, self.valid_signature, self.messages[:-1])
        result = verify(request)
        self.assertFalse(result,
                         "Verification should fail because number of verification messages differ from the "
                         "messages that were signed.")


if __name__ == '__main__':
    unittest.main()
