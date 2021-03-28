from typing import Optional, Union

from ursa_bbs_signatures.foreign_function_interface.bindings.bls import (
    bls_generate_blinded_g1_key,
    bls_generate_blinded_g2_key,
)
from ursa_bbs_signatures.foreign_function_interface.ffi_util import encode_bytes
from .BlsKeyPair import BlsKeyPair


class BlindedBlsKeyPair(BlsKeyPair):
    def __init__(self, public_key: bytes, secret_key: bytes, blinding_factor: bytes):
        super().__init__(public_key, secret_key=secret_key)
        self.blinding_factor = blinding_factor

    @classmethod
    def generate_g1(
        cls, seed: Optional[Union[str, bytes]] = None
    ) -> "BlindedBlsKeyPair":
        if seed:
            seed = encode_bytes(seed)
        res = bls_generate_blinded_g1_key(seed)
        return cls(res["public_key"], res["secret_key"], res["blinding_factor"])

    @classmethod
    def generate_g2(
        cls, seed: Optional[Union[str, bytes]] = None
    ) -> "BlindedBlsKeyPair":
        if seed:
            seed = encode_bytes(seed)
        res = bls_generate_blinded_g2_key(seed)
        return cls(res["public_key"], res["secret_key"], res["blinding_factor"])
