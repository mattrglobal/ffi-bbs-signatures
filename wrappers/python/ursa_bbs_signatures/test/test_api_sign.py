import unittest

from ursa_bbs_signatures import BlsKeyPair, sign, SignRequest, BbsException
from ursa_bbs_signatures._ffi.bindings.bbs_sign import bbs_signature_size


class TestApiSign(unittest.TestCase):
    def setUp(self) -> None:
        self.public_bls_key = b"\x86M\xc0cUPQ\xdb\xdblE\x87E\x832p8\xf5\xb9\xbeM\x05\xf1G\x9emHe\x99\xf0T\xbfn\x85" \
                              b"\x18\xdb\x86'W\x1c\xe3" \
                              b"\x8aG\x97S\x01\xda\xfe\x0e\x15)\x144I\xf9\xd0:\xcc\xdb\xc5\xc26\x10\xf9@\xaa\x18\xf5," \
                              b"6Es\xfd\xc7\xf1tcZ\x98\xfe\xd6\xcct\xbfk\xfb\x9f\xf1\xad)\x15\x88w\x80\xdd\xea "
        self.secret_bls_key = b'\x06\xe7w\xf4\x90\x0e\xacK\xb7\x94l\x00/\xaaFD\x1c\xff\x9c\xad\xdcq\xed\xb6#%\x7fu' \
                              b'\xc7\x8c\xfe\x9c '
        self.invalid_secret_bls_key = b'j\xf2\xf1abM\xd3\xa5Kumz6\xeaK\x1c\x03\xac\x97"(' \
                                      b'kR\xdd\x84#]\xea\x82\xfb\x86\xf1 '
        self.messages = [
            "message 1",
            "message 2",
            "message 3",
            "message 4",
            "message 5",
        ]


    def test_get_signature_size(self):
        result = bbs_signature_size()
        self.assertEqual(result, 112, "Signature size should be 112")

    def test_signature_length(self):
        key = BlsKeyPair.generate_g2()
        signature = sign(SignRequest(key, ['test']))
        self.assertIsNotNone(signature, "Signature should not be None")
        self.assertEqual(len(signature), bbs_signature_size())

    def test_sign_success(self):
        key_pair = BlsKeyPair(self.public_bls_key, self.secret_bls_key)
        sign_request = SignRequest(key_pair, self.messages)
        signature = sign(sign_request)
        self.assertIsInstance(signature, bytes, f"Signature should be of type 'bytes', not {type(signature)}")

    def test_sign_no_secret_key(self):
        key_pair = BlsKeyPair(self.public_bls_key)
        sign_request = SignRequest(key_pair, self.messages)
        with self.assertRaises(BbsException, msg="Should raise a BbsExceptions because of the missing secret key."):
            sign(sign_request)


if __name__ == '__main__':
    unittest.main()
