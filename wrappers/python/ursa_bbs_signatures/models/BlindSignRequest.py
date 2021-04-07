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
        """A request to create a BBS signature that features blinded/committed messages

        Args:
            secret_key: The secret key of the signer
            public_key: The public key of the signer
            commitment: The resulting commitment of the blinded messages to sign
            messages: The known messages to sign
        """
        self.secret_key = secret_key
        self.public_key = public_key
        self.commitment = commitment
        self.messages = messages
