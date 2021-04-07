from typing import List
from .keys import BlsKeyPair


class VerifyRequest:
    def __init__(
        self, key_pair: BlsKeyPair, signature: bytes, messages: List[str]
    ) -> None:
        """ A request to verify a BBS signature for a set of messages

        Args:
            key_pair: Public key of the signer of the signature
            signature: Raw signature value
            messages: Messages that were signed to produce the signature
        """
        self.key_pair = key_pair
        self.signature = signature
        self.messages = messages
