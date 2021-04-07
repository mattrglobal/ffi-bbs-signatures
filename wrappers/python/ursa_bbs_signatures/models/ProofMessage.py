from enum import IntEnum, unique

@unique
class ProofMessageType(IntEnum):
    Revealed = 1
    HiddenProofSpecificBlinding = 2
    HiddenExternalBlinding = 3


class ProofMessage:
    def __init__(
        self,
        message: str,
        proof_type: ProofMessageType,
    ) -> None:
        """A class to hold proof messages

        Args:
            message: The message
            proof_type: The proof type
        """
        self.proof_type = proof_type
        self.message = message

    def __repr__(self) -> str:
        """Converts the object to a string representation
        Returns: a string representation
        """
        return f"{self.proof_type.name}: {self.message}"

    def __hash__(self) -> int:
        """Returns the hash value of self
        Returns: The hashed object
        """
        return hash(f"{self.message}{self.proof_type.value}")

    def __eq__(self, o: "ProofMessage") -> bool:
        """ Enables the usage of the == operator
        """
        return self.message == o.message and self.proof_type.value == o.proof_type.value

    def __ne__(self, o: object) -> bool:
        """ Enables the usage of the != operator
        """
        return not self.__eq__(o)