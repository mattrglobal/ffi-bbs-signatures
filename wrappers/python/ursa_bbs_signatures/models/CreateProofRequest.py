from typing import List, Optional

from .ProofMessage import ProofMessage, ProofMessageType

from .keys import BbsKey


class CreateProofRequest:
    def __init__(
        self,
        public_key: BbsKey,
        messages: List[ProofMessage],
        signature: bytes,
        nonce: bytes,
        blinding_factor: Optional[bytes] = None,
    ) -> None:
        # Check wether there are any messages with type HiddenExternalBlinding
        has_hidden_blinding = any(
            [x.proof_type == ProofMessageType.HiddenExternalBlinding for x in messages]
        )

        # Raise an exception if the former is true and no blinding factor was provided
        if has_hidden_blinding and not blinding_factor:
            raise TypeError("Blinding factor must be provided")

        self.key = public_key
        self.messages = messages
        self.signature = signature
        self.nonce = nonce
        self.blinding_factor = blinding_factor
