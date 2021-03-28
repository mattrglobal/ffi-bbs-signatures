from enum import IntEnum, unique
from typing import Optional


@unique
class ProofMessageType(IntEnum):
    Revealed = 1
    HiddenProofSpecificBlinding = 2
    HiddenExternalBlinding = 3


class ProofMessage:
    def __init__(
        self,
        message: bytes,
        proof_type: ProofMessageType,
        blinding_factor: Optional[bytes] = None,
    ) -> None:
        self.proof_type = proof_type
        self.message = message
        self.blinding_factor = blinding_factor

    def __repr__(self) -> str:
        return f"{self.proof_type.name}: {self.message}"

    def __hash__(self) -> int:
        return hash(f"{self.message}{self.proof_type.value}")

    def __eq__(self, o: "ProofMessage") -> bool:
        return self.message == o.message and self.proof_type.value == o.proof_type.value

    def __ne__(self, o: object) -> bool:
        return not self.__eq__(o)