class UnblindSignatureRequest:

    def __init__(self, blinded_signature: bytes, blinding_factor: bytes) -> None:
        """ Unblind Signature Request

        Args:
            blinded_signature: The blinded signature
            blinding_factor: The blinding factor
        """
        self.blinded_signature = blinded_signature
        self.blinding_factor = blinding_factor
