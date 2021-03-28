from typing import List
from .keys import BbsKey, BlsKeyPair
from .IndexedMessage import IndexedMessage


class BlindSignRequest:
    def __init__(
        self,
        secret_key: BlsKeyPair,
        public_key: BbsKey,
        commitment: bytes,
        messages: List[IndexedMessage],
    ) -> None:
        self.secret_key = secret_key
        self.public_key = public_key
        self.commitment = commitment
        self.messages = messages
