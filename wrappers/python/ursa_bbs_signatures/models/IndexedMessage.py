class IndexedMessage:

    __slots__ = ("message", "index")

    def __init__(self, message: str, index: int) -> None:
        self.message = message
        self.index = index
