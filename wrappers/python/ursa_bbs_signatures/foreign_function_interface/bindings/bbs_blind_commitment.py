import sys
from ctypes import POINTER, byref, c_char_p, c_uint, c_ulong

from ..ExternError import ExternError
from ..ffi_util import (
    FfiByteBuffer,
    encode_str,
    wrap_native_func,
)

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


# Return type models
class BlindCommitmentContextFinishReturnType(TypedDict):
    commitment: FfiByteBuffer
    out_context: FfiByteBuffer
    blinding_factor: FfiByteBuffer


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
        "commitment": commitment,
        "out_context": out_context,
        "blinding_factor": blinding_factor,
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
    handle: int, index: int, message: FfiByteBuffer
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_add_message_bytes",
        arg_types=[c_ulong, c_uint, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, message, byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_add_message_prehashed(
    handle: int, index: int, message: FfiByteBuffer
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_add_message_prehashed",
        arg_types=[c_ulong, c_uint, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, message, byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_public_key(
    handle: int, value: FfiByteBuffer
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_public_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, value, byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_nonce_string(handle: int, value: str) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_public_key",
        arg_types=[c_ulong, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_str(value), byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_nonce_bytes(
    handle: int, value: FfiByteBuffer
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_nonce_bytes",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, value, byref(err))
    err.throw_on_error()


def bbs_blind_commitment_context_set_nonce_prehashed(
    handle: int, value: FfiByteBuffer
) -> None:
    func = wrap_native_func(
        "bbs_blind_commitment_context_set_nonce_prehashed",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, value, byref(err))
    err.throw_on_error()