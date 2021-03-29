from typing import List
from .IndexedMessage import IndexedMessage
from .keys import BbsKey


class VerifyBlindedCommitmentRequest:
    def __init__(
        self,
        public_key: BbsKey,
        proof: bytes,
        blinded_indices: List[IndexedMessage],
        nonce: bytes,
    ) -> None:
        self.public_key = public_key
        self.proof = proof
        self.blinded_indices = blinded_indices
        self.nonce = nonce
