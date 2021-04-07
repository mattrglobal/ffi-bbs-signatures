from typing import List
from .keys import BlsKeyPair


class SignRequest:
    def __init__(self, key_pair: BlsKeyPair, messages: List[str]) -> None:
        """ A request to create a BBS signature for a set of messages from a BLS12-381 key pair
        Args:
            key_pair: BLS12-381 key pair
            messages: Messages to sign
        """
        self.key_pair = key_pair
        self.messages = messages
