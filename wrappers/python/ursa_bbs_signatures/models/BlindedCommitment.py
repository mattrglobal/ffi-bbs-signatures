class BlindedCommitment:

    def __init__(self, blind_sign_context: bytes, blinding_factor: bytes, commitment: bytes) -> None:
        """Class to represent a blinded commitment

        Args:
            blind_sign_context: The blinded sign context
            blinding_factor: The blinding factor
            commitment: The commitment
        """
        self.blind_sign_context = blind_sign_context
        self.blinding_factor = blinding_factor
        self.commitment = commitment
