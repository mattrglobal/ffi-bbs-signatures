class BbsKey:
    def __init__(self, public_key: bytes, message_count: int) -> None:
        self.public_key = public_key
        self.message_count = message_count
