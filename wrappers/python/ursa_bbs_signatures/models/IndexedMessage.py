class IndexedMessage:

    __slots__ = ("message", "index")

    def __init__(self, message: str, index: int) -> None:
        """Represents a message and its index within a collection

        Args:
            message: The message
            index:  The message index
        """
        self.message = message
        self.index = index
