from typing import List
from .keys import BbsKey


class VerifyProofRequest:
    def __init__(
        self, public_key: BbsKey, proof: bytes, messages: List[str], nonce: bytes
    ) -> None:
        """ Verify Proof Request

        Args:
            public_key: The public key
            proof: The proof
            messages: The messages
            nonce: The nonce
        """
        self.key = public_key
        self.proof = proof
        self.messages = messages
        self.nonce = nonce
