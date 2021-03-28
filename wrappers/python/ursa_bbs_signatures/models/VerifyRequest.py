from typing import List
from .keys import BlsKeyPair


class VerifyRequest:
    def __init__(
        self, key_pair: BlsKeyPair, signature: bytes, messages: List[str]
    ) -> None:
        self.key_pair = key_pair
        self.signature = signature
        self.messages = messages
