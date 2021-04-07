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
        """A request object for creating proofs

        Args:
            public_key (): Public key of the original signer of the signature
            messages (): The messages that were originally signed
            signature (): BBS signature to generate the BBS proof from
            nonce (): A nonce for the resulting proof
            blinding_factor (): The blinding factor used in blinded signature, if any messages are hidden using
                ProofMessageType.HiddenExternalBlinding
        """
        # Check weather there are any messages with type HiddenExternalBlinding
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
