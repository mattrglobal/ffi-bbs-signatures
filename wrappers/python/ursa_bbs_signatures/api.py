from ._ffi.bindings import (
    bbs_sign,
    bbs_verify,
    bbs_blind_sign,
    bbs_create_proof,
    bbs_verify_proof,
    bbs_blind_commitment,
    bbs_verify_blind_commitment
)

from .models.BbsException import BbsException
from .models.BlindSignRequest import BlindSignRequest
from .models.BlindedCommitment import BlindedCommitment
from .models.CreateBlindedCommitmentRequest import CreateBlindedCommitmentRequest
from .models.CreateProofRequest import CreateProofRequest
from .models.SignRequest import SignRequest
from .models.SignatureProofStatus import SignatureProofStatus
from .models.UnblindSignatureRequest import UnblindSignatureRequest
from .models.VerifyBlindedCommitmentRequest import VerifyBlindedCommitmentRequest
from .models.VerifyProofRequest import VerifyProofRequest
from .models.VerifyRequest import VerifyRequest


def sign(request: SignRequest) -> bytes:
    """Signs a set of messages with a BBS key pair and produces a BBS signature
    Args:
        request: Request for the sign operation
    Raises:
        BbsException: if the secret key cannot be found.
    Returns:
        The raw signature value
    """
    if not request.key_pair.secret_key:
        raise BbsException("Secret key not found")

    bbs_key_pair = request.key_pair.get_bbs_key(len(request.messages))

    handle = bbs_sign.bbs_sign_context_init()

    for msg in request.messages:
        bbs_sign.bbs_sign_context_add_message_string(handle, msg)

    bbs_sign.bbs_sign_context_set_public_key(handle, bbs_key_pair.public_key)

    bbs_sign.bbs_sign_context_set_secret_key(handle, request.key_pair.secret_key)

    signature = bbs_sign.bbs_sign_context_finish(handle)

    return bytes(signature)


def verify(request: VerifyRequest) -> bool:
    """Verifies a BBS+ signature for a set of messages with a BBS public key
    Args:
        request: Request for the signature verification operation
    Returns:
        True if the signature is valid, otherwise False
    """
    bbs_key_pair = request.key_pair.get_bbs_key(len(request.messages))

    handle = bbs_verify.bbs_verify_context_init()

    bbs_verify.bbs_verify_context_set_public_key(handle, bbs_key_pair.public_key)

    bbs_verify.bbs_verify_context_set_signature(handle, request.signature)

    for msg in request.messages:
        bbs_verify.bbs_verify_context_add_message_string(handle, msg)

    result = bbs_verify.bbs_verify_context_finish(handle)
    return result == 0


def blind_sign(request: BlindSignRequest) -> bytes:
    """Signs a set of messages featuring both known and blinded messages to the signer and produces a BBS+ signature
    Args:
        request: Request for the blind sign operation
    Returns:
        Raw signature value
    """
    handle = bbs_blind_sign.bbs_blind_sign_context_init()

    for item in request.messages:
        bbs_blind_sign.bbs_blind_sign_context_add_message_string(handle, item.index, item.message)

    bbs_blind_sign.bbs_blind_sign_context_set_public_key(handle, request.public_key.public_key)

    bbs_blind_sign.bbs_blind_sign_context_set_secret_key(handle, request.secret_key.secret_key)

    bbs_blind_sign.bbs_blind_sign_context_set_commitment(handle, request.commitment)

    return bbs_blind_sign.bbs_blind_sign_context_finish(handle)


def unblind_signature(request: UnblindSignatureRequest) -> bytes:
    """Unblinds the signature asynchronous.
    Args:
        request: Request for the unblinding operation
    Returns:
        Unblinded signature
    """
    return bbs_blind_sign.bbs_unblind_signature(request.blinded_signature, request.blinding_factor)


def create_blinded_commitment(
        request: CreateBlindedCommitmentRequest,
) -> BlindedCommitment:
    """Create a blinded commitment of messages for use in producing a blinded BBS+ signature
    Args:
        request: Request for producing the blinded commitment
    Returns:
        The blinded commitment
    """
    handle = bbs_blind_commitment.bbs_blind_commitment_context_init()

    for item in request.messages:
        bbs_blind_commitment.bbs_blind_commitment_context_add_message_string(
            handle, item.index, item.message
        )

    bbs_blind_commitment.bbs_blind_commitment_context_set_nonce_bytes(handle, request.nonce)

    bbs_blind_commitment.bbs_blind_commitment_context_set_public_key(handle, request.public_key.public_key)

    res = bbs_blind_commitment.bbs_blind_commitment_context_finish(handle)

    return BlindedCommitment(
        res["out_context"], res["blinding_factor"], res["commitment"]
    )


def verify_blinded_commitment(
        request: VerifyBlindedCommitmentRequest,
) -> SignatureProofStatus:
    """Verifies a blinded commitment of messages
    Args:
        request: Request for the commitment verification
    Returns:
        The resulting proof status
    """
    handle = bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_init()

    bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_nonce_bytes(request.nonce)

    bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_proof(request.proof)

    bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_public_key(request.public_key)

    for item in request.blinded_indices:
        bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_add_blinded(handle, item.index)

    result = bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_finish(handle)

    return SignatureProofStatus(result)


def create_proof(request: CreateProofRequest) -> bytes:
    """Creates the proof asynchronous.
    Args:
        request: Request for creating the proof
    Returns:
        The proof
    """
    handle = bbs_create_proof.bbs_create_proof_context_init()

    for msg in request.messages:
        bbs_create_proof.bbs_create_proof_context_add_proof_message_string(
            handle, msg.message, msg.proof_type, request.blinding_factor
        )

    bbs_create_proof.bbs_create_proof_context_set_nonce_bytes(handle, request.nonce)

    bbs_create_proof.bbs_create_proof_context_set_public_key(handle, request.key.public_key)

    bbs_create_proof.bbs_create_proof_context_set_signature(handle, request.signature)

    return bbs_create_proof.bbs_create_proof_context_finish(handle)


def verify_proof(request: VerifyProofRequest) -> bool:
    """Verifies the proof
    Args:
        request: Request for the proof verification operation
    Return:
        True if verification was successful, False if not
    """
    handle = bbs_verify_proof.bbs_verify_proof_context_init()

    bbs_verify_proof.bbs_verify_proof_context_set_public_key(handle, request.key.public_key)

    bbs_verify_proof.bbs_verify_proof_context_set_nonce_bytes(handle, request.nonce)

    bbs_verify_proof.bbs_verify_proof_context_set_proof(handle, request.proof)

    for msg in request.messages:
        bbs_verify_proof.bbs_verify_proof_context_add_message_string(handle, msg)

    result = bbs_verify_proof.bbs_verify_proof_context_finish(handle)

    return result == 0


def get_total_message_count(proof: bytes) -> int:
    """Returns the total amount of messages for a given proof
    Args:
        proof: a bytes object containing the proof value
    Returns:
        The amount of messages.
    """
    return bbs_verify_proof.bbs_get_total_messages_count_for_proof(proof)
