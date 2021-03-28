from typing import List
from .keys import BbsKey


class VerifyProofRequest:
    def __init__(
        self, public_key: BbsKey, proof: bytes, messages: List[str], nonce: bytes
    ) -> None:
        self.key = public_key
        self.proof = proof
        self.messages = messages
        self.nonce = nonce
