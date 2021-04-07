from typing import Optional, Union

from .BbsKey import BbsKey
from ..._ffi.bindings.bls import (
    bls_public_key_g1_size,
    bls_public_key_g2_size,
    bls_secret_key_to_bbs_key,
    bls_public_key_to_bbs_key,
    bls_generate_g1_key,
    bls_generate_g2_key,
    bls_get_public_key, bls_secret_key_size
)
from ...models.BbsException import BbsException


class BlsKeyPair:
    def __init__(self, public_key: bytes, secret_key: Optional[bytes] = None) -> None:
        """ A BLS 12-381 key pair

        Args:
            public_key: The deterministic public key
            secret_key: The secret key
        """
        self.public_key = public_key
        self.secret_key = secret_key

    @staticmethod
    def public_g1_key_size() -> int:
        return bls_public_key_g1_size()

    @staticmethod
    def public_g2_key_size() -> int:
        return bls_public_key_g2_size()

    @staticmethod
    def secret_key_size() -> int:
        return bls_secret_key_size()

    @property
    def is_g1(self) -> bool:
        return len(self.public_key) == bls_public_key_g1_size()

    @property
    def is_g2(self) -> bool:
        return len(self.public_key) == bls_public_key_g2_size()

    def get_bbs_key(self, message_count: int) -> BbsKey:
        if self.secret_key:
            pub_key = bls_secret_key_to_bbs_key(self.secret_key, message_count)
            return BbsKey(bytes(pub_key), message_count)
        elif self.is_g2:
            pub_key = bls_public_key_to_bbs_key(self.public_key, message_count)
            return BbsKey(bytes(pub_key), message_count)

        raise BbsException("Cannot generate BbsKey from G1 public key")

    @classmethod
    def generate_g1(cls, seed: Optional[Union[str, bytes]] = None) -> "BlsKeyPair":
        res = bls_generate_g1_key(seed)

        return cls(res["public_key"], res["secret_key"])

    @classmethod
    def generate_g2(cls, seed: Optional[Union[str, bytes]] = None) -> "BlsKeyPair":
        res = bls_generate_g2_key(seed)

        return cls(res["public_key"], res["secret_key"])

    @classmethod
    def from_secret_key(cls, secret_key: bytes) -> "BlsKeyPair":
        pub_key = bls_get_public_key(secret_key)
        return cls(pub_key, secret_key)
