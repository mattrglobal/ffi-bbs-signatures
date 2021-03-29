class UnblindSignatureRequest:

    def __init__(self, blinded_signature: bytes, blinding_factor: bytes) -> None:
        self.blinded_signature = blinded_signature
        self.blinding_factor = blinding_factor
