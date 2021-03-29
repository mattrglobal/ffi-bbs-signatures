from typing import List
from .keys import BbsKey
from .IndexedMessage import IndexedMessage


class CreateBlindedCommitmentRequest:

    def __init__(self, public_key: BbsKey, messages: List[IndexedMessage], nonce: bytes) -> None:
        self.public_key = public_key
        self.messages = messages
        self.nonce = nonce
