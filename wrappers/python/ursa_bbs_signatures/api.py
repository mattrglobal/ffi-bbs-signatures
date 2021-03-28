from .foreign_function_interface.bindings.bbs_create_proof import (
    bbs_create_proof_context_add_proof_message_string,
    bbs_create_proof_context_finish,
    bbs_create_proof_context_init,
    bbs_create_proof_context_set_nonce_bytes,
    bbs_create_proof_context_set_public_key,
    bbs_create_proof_context_set_signature,
)
from .foreign_function_interface.bindings.bbs_sign import (
    bbs_sign_context_add_message_string,
    bbs_sign_context_finish,
    bbs_sign_context_init,
    bbs_sign_context_set_public_key,
    bbs_sign_context_set_secret_key,
)
from .foreign_function_interface.bindings.bbs_verify import (
    bbs_verify_context_add_message_string,
    bbs_verify_context_finish,
    bbs_verify_context_init,
    bbs_verify_context_set_public_key,
    bbs_verify_context_set_signature,
)
from .foreign_function_interface.bindings.bbs_verify_proof import (
    bbs_get_total_messages_count_for_proof,
    bbs_verify_proof_context_add_message_string,
    bbs_verify_proof_context_finish,
    bbs_verify_proof_context_init,
    bbs_verify_proof_context_set_nonce_bytes,
    bbs_verify_proof_context_set_proof,
    bbs_verify_proof_context_set_public_key,
)
from .models.BbsException import BbsException
from .models.BlindSignRequest import BlindSignRequest
from .models.CreateProofRequest import CreateProofRequest
from .models.SignRequest import SignRequest
from .models.VerifyProofRequest import VerifyProofRequest
from .models.VerifyRequest import VerifyRequest


def sign(request: SignRequest) -> bytes:
    if not request.key_pair.secret_key:
        raise BbsException("Secret key not found")

    bbs_key_pair = request.key_pair.get_bbs_key(len(request.messages))

    handle = bbs_sign_context_init()

    for msg in request.messages:
        bbs_sign_context_add_message_string(handle, msg)

    bbs_sign_context_set_public_key(handle, bbs_key_pair.public_key)

    bbs_sign_context_set_secret_key(handle, request.key_pair.secret_key)

    signature = bbs_sign_context_finish(handle)

    return bytes(signature)


def verify(request: VerifyRequest) -> bool:
    bbs_key_pair = request.key_pair.get_bbs_key(len(request.messages))

    handle = bbs_verify_context_init()

    bbs_verify_context_set_public_key(handle, bbs_key_pair.public_key)

    bbs_verify_context_set_signature(handle, request.signature)

    for msg in request.messages:
        bbs_verify_context_add_message_string(handle, msg)

    result = bbs_verify_context_finish(handle)
    return result == 0


def blind_sign(request: BlindSignRequest) -> bytes:
    raise NotImplementedError()


def unblind_signature() -> bytes:
    raise NotImplementedError()


def create_blinded_commitment():
    raise NotImplementedError()


def verify_blinded_commitment():
    raise NotImplementedError()


def create_proof(request: CreateProofRequest) -> bytes:
    handle = bbs_create_proof_context_init()

    for msg in request.messages:
        bbs_create_proof_context_add_proof_message_string(
            handle, msg.message, msg.proof_type, request.blinding_factor
        )

    bbs_create_proof_context_set_nonce_bytes(handle, request.nonce)

    bbs_create_proof_context_set_public_key(handle, request.key.public_key)

    bbs_create_proof_context_set_signature(handle, request.signature)

    return bbs_create_proof_context_finish(handle)


def verify_proof(request: VerifyProofRequest) -> bool:
    handle = bbs_verify_proof_context_init()

    bbs_verify_proof_context_set_public_key(handle, request.key.public_key)

    bbs_verify_proof_context_set_nonce_bytes(handle, request.nonce)

    bbs_verify_proof_context_set_proof(handle, request.proof)

    for msg in request.messages:
        bbs_verify_proof_context_add_message_string(handle, msg)

    result = bbs_verify_proof_context_finish(handle)

    return result == 0


def get_total_message_count(proof: bytes) -> int:
    return bbs_get_total_messages_count_for_proof(proof)
