from ctypes import POINTER, byref, c_char_p, c_int, c_uint, c_ulong

import sys

from ..ExternError import ExternError

from ..ffi_util import (
    FfiByteBuffer, encode_bytes,
    encode_str,
    wrap_native_func,
)

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

# Binding functions
def bbs_blind_sign_context_init() -> int:
    func = wrap_native_func(
        "bbs_blind_sign_context_init",
        arg_types=[POINTER(ExternError)],
        return_type=c_ulong,
    )
    err = ExternError()
    handle = func(byref(err))
    err.throw_on_error()
    return handle

def bbs_blind_sign_context_finish(handle: int) -> bytes:
    func = wrap_native_func(
        "bbs_blind_sign_context_finish",
        arg_types=[c_ulong, POINTER(FfiByteBuffer), POINTER(ExternError)],
        return_type=c_int,
    )
    bl_sig, err = FfiByteBuffer(), ExternError()
    func(handle, byref(bl_sig), byref(err))
    err.throw_on_error()
    return bytes(bl_sig)


def bbs_blind_sign_context_add_message_string(
    handle: int, index: int, message: str
) -> None:
    func = wrap_native_func(
        "bbs_blind_sign_context_add_message_string",
        arg_types=[c_ulong, c_uint, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, encode_str(message), byref(err))
    err.throw_on_error()


def bbs_blind_sign_context_add_message_bytes(
    handle: int, index: int, message: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_sign_context_add_message_bytes",
        arg_types=[c_ulong, c_uint, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, encode_bytes(message), byref(err))
    err.throw_on_error()


def bbs_blind_sign_context_add_message_prehashed(
    handle: int, index: int, message: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_sign_context_add_message_prehashed",
        arg_types=[c_ulong, c_uint, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, encode_bytes(message), byref(err))
    err.throw_on_error()


def bbs_blind_sign_context_set_public_key(
    handle: int, public_key: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_sign_context_set_public_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(public_key), byref(err))
    err.throw_on_error()


def bbs_blind_sign_context_set_secret_key(
    handle: int, secret_key: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_sign_context_set_secret_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(secret_key), byref(err))
    err.throw_on_error()


def bbs_blind_sign_context_set_commitment(
    handle: int, commitment: bytes
) -> None:
    func = wrap_native_func(
        "bbs_blind_sign_context_set_commitment",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(commitment), byref(err))
    err.throw_on_error()


def bbs_unblind_signature(
    blind_signature: bytes, blinding_factor: bytes
) -> bytes:
    func = wrap_native_func(
        "bbs_unblind_signature",
        arg_types=[
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(FfiByteBuffer),
            POINTER(ExternError),
        ],
    )
    unblind_signature, err = FfiByteBuffer(), ExternError()
    func(encode_bytes(blind_signature), encode_bytes(blinding_factor), byref(unblind_signature), byref(err))
    err.throw_on_error()

    return bytes(unblind_signature)


__all__ = [
    bbs_blind_sign_context_init,
    bbs_blind_sign_context_finish,
    bbs_blind_sign_context_add_message_string,
    bbs_blind_sign_context_add_message_bytes,
    bbs_blind_sign_context_add_message_prehashed,
    bbs_blind_sign_context_set_public_key,
    bbs_blind_sign_context_set_secret_key,
    bbs_blind_sign_context_set_commitment,
    bbs_unblind_signature
]
