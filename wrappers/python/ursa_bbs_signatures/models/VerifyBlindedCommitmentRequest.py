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
        """ Verify Blinded Commitment Request

        Args:
            public_key: The pubic key
            proof: The proof
            blinded_indices: The blinded indices
            nonce: The nonce
        """
        self.public_key = public_key
        self.proof = proof
        self.blinded_indices = blinded_indices
        self.nonce = nonce
