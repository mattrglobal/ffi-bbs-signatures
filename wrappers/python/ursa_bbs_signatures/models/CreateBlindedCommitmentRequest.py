from typing import List
from .keys import BbsKey
from .IndexedMessage import IndexedMessage


class CreateBlindedCommitmentRequest:

    def __init__(self, public_key: BbsKey, messages: List[IndexedMessage], nonce: bytes) -> None:
        """A request to create a BBS signature that features blinded/committed messages

        Args:
            public_key: The public key
            messages: The messages
            nonce: The nonce
        """
        self.public_key = public_key
        self.messages = messages
        self.nonce = nonce
