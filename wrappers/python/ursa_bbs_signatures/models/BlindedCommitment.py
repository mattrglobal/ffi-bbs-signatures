class BlindedCommitment:

    def __init__(self, blind_sign_context: bytes, blinding_factor: bytes, commitment: bytes) -> None:
        self.blind_sign_context = blind_sign_context
        self.blinding_factor = blinding_factor
        self.commitment = commitment
