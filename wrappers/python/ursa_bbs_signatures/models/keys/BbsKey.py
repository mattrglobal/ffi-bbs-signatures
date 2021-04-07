class BbsKey:
    def __init__(self, public_key: bytes, message_count: int) -> None:
        """ A BBS+ key pair

        Args:
            public_key: Raw public key value for the key pair
            message_count: Number of messages that can be signed
        """
        self.public_key = public_key
        self.message_count = message_count
