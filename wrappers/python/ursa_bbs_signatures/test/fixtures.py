from pytest import fixture

from ursa_bbs_signatures import SignRequest
from ursa_bbs_signatures.models.keys.BlsKeyPair import BlsKeyPair


@fixture
def public_bls_key_1() -> bytes:
    return b"\x86M\xc0cUPQ\xdb\xdblE\x87E\x832p8\xf5\xb9\xbeM\x05\xf1G\x9emHe\x99\xf0T\xbfn\x85\x18\xdb\x86'W\x1c\xe3" \
           b"\x8aG\x97S\x01\xda\xfe\x0e\x15)\x144I\xf9\xd0:\xcc\xdb\xc5\xc26\x10\xf9@\xaa\x18\xf5," \
           b"6Es\xfd\xc7\xf1tcZ\x98\xfe\xd6\xcct\xbfk\xfb\x9f\xf1\xad)\x15\x88w\x80\xdd\xea "


@fixture
def valid_secret_bls_key() -> bytes:
    return b'\x06\xe7w\xf4\x90\x0e\xacK\xb7\x94l\x00/\xaaFD\x1c\xff\x9c\xad\xdcq\xed\xb6#%\x7fu\xc7\x8c\xfe\x9c'


@fixture
def invalid_secret_bls_key() -> bytes:
    return b'j\xf2\xf1abM\xd3\xa5Kumz6\xeaK\x1c\x03\xac\x97"(kR\xdd\x84#]\xea\x82\xfb\x86\xf1'


@fixture
def valid_bls_signing_key_pair(public_bls_key_1, valid_secret_bls_key) -> BlsKeyPair:
    return BlsKeyPair(public_bls_key_1, valid_secret_bls_key)


@fixture
def invalid_bls_signing_key_pair(public_bls_key_1, invalid_secret_bls_key) -> BlsKeyPair:
    """Key pair with non-matching public and secret keys"""
    return BlsKeyPair(public_bls_key_1, invalid_secret_bls_key)

@fixture
def only_public_key_bls_signing_key_pair(public_bls_key_1) -> BlsKeyPair:
    return BlsKeyPair(public_bls_key_1)

@fixture
def messages():
    return [
        "message 1",
        "message 2",
        "message 3",
        "message 4",
        "message 5",
    ]


@fixture
def valid_sign_request(valid_bls_signing_key_pair, messages):
    return SignRequest(valid_bls_signing_key_pair, messages)


@fixture
def invalid_sign_request(invalid_bls_signing_key_pair, messages):
    return SignRequest(invalid_bls_signing_key_pair, messages)
