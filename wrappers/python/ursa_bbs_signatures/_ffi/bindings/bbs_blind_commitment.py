import sys
from ctypes import POINTER, byref, c_char_p, c_uint, c_ulong

from ..ExternError import ExternError
from ..ffi_util import (
    FfiByteBuffer,
    encode_bytes,
    encode_str,
    wrap_native_func,
)

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


# Return type models
class BlindCommitmentContextFinishReturnType(TypedDict):
    commitment: bytes
    out_context: bytes
    blinding_factor: bytes


# Binding functions
def bbs_blind_signature_size() -> int:
    func = wrap_native_func("bbs_blind_signature_size")
    return func()


def bbs_blind_commitment_context_init() -> int:
    func = wrap_native_func(
        "bbs_blind_commitment_context_init",
        arg_types=[POINTER(ExternError)],
        return_type=c_ulong,
    )
    err = ExternError()
    handle = func(byref(err))

    err.throw_on_error()

    return handle


def bbs_blind_commitment_context_finish(
    handle: int,
) -> BlindCommitmentContextFinishReturnType:
    func = wrap_native_func(
        "bbs_blind_commitment_context_finish",
        arg_types=[
            c_ulong,
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(ExternError),
        ],
    )

    commitment, out_context, blinding_factor, err = (
        FfiByteBuffer(),
        FfiByteBuffer(),
        FfiByteBuffer(),
        ExternError(),
    )
    func(
        handle,
        byref(commitment),
        byref(out_context),
        byref(blinding_factor),
        byref(err),
    )

    err.throw_on_error()

    return {
        "commitment": bytes(commitment),
        "out_context": bytes(out_context),
        "blinding_factor": bytes(blinding_factor),
    }


def bbs_blind_commitment_context_add_message_string(
    handle: int, index: int, message: str
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_add_message_string",
        arg_types=[c_ulong, c_uint, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, encode_str(message), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_add_message_bytes(
    handle: int, index: int, message: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_add_message_bytes",
        arg_types=[c_ulong, c_uint, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, encode_bytes(message), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_add_message_prehashed(
    handle: int, index: int, message: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_add_message_prehashed",
        arg_types=[c_ulong, c_uint, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, encode_bytes(message), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_public_key(handle: int, value: bytes) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_public_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(value), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_nonce_string(handle: int, value: str) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_public_key",
        arg_types=[c_ulong, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_str(value), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_nonce_bytes(handle: int, value: bytes) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_nonce_bytes",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(value), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_nonce_prehashed(handle: int, value: bytes) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_nonce_prehashed",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(value), byref(err))
    err.throw_on_error()


__all__ = [
    bbs_blind_signature_size,
    bbs_blind_commitment_context_init,
    bbs_blind_commitment_context_finish,
    bbs_blind_commitment_context_add_message_string,
    bbs_blind_commitment_context_add_message_bytes,
    bbs_blind_commitment_context_add_message_prehashed,
    bbs_blind_commitment_context_set_public_key,
    bbs_blind_commitment_context_set_nonce_string,
    bbs_blind_commitment_context_set_nonce_bytes,
    bbs_blind_commitment_context_set_nonce_prehashed,
]