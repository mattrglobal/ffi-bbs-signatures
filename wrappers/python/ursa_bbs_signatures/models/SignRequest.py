from typing import List
from .keys import BlsKeyPair


class SignRequest:
    def __init__(self, key_pair: BlsKeyPair, messages: List[str]) -> None:
        self.key_pair = key_pair
        self.messages = messages
