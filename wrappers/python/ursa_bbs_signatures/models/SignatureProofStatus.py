from enum import IntEnum


class SignatureProofStatus(IntEnum):
    success = 200
    bad_signature = 400
    bad_hidden_signature = 401
    bad_revealed_message = 402
