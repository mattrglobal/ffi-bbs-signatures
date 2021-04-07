from ctypes import POINTER, byref, c_char_p, c_long, c_uint, c_ulong, c_uint32, c_uint64
import sys
from typing import Optional, Union
from ..ExternError import ExternError

from ..ffi_util import FfiByteBuffer, encode_bytes, wrap_native_func


if sys.version_info >= (3, 8):
    from typing import TypedDict  # pylint: disable=no-name-in-module
else:
    from typing_extensions import TypedDict


def bbs_verify_blind_commitment_context_init() -> int:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_init",
        arg_types=[POINTER(ExternError)],
        return_type=c_uint64,
    )
    err = ExternError()
    handle = func(err)
    err.throw_on_error()
    return handle


def bbs_verify_blind_commitment_context_add_blinded(handle: int, index: int) -> None:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_add_blinded",
        arg_types=[c_uint64, c_uint32, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, index, err)
    err.throw_on_error()


def bbs_verify_blind_commitment_context_set_public_key(
    handle: int, public_key: FfiByteBuffer
) -> None:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_set_public_key",
        arg_types=[c_uint64, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, public_key, err)
    err.throw_on_error()


def bbs_verify_blind_commitment_context_set_nonce_string(
    handle: int, nonce: str
) -> None:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_set_nonce_string",
        arg_types=[c_uint64, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, nonce, err)
    err.throw_on_error()


def bbs_verify_blind_commitment_context_set_nonce_bytes(
    handle: int, nonce: bytes
) -> None:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_set_nonce_bytes",
        arg_types=[c_uint64, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(nonce), err)
    err.throw_on_error()


def bbs_verify_blind_commitment_context_set_nonce_prehashed(
    handle: int, nonce: bytes
) -> None:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_set_nonce_prehashed",
        arg_types=[c_uint64, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(nonce), err)
    err.throw_on_error()


def bbs_verify_blind_commitment_context_set_proof(
    handle: int, proof: bytes
) -> None:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_set_proof",
        arg_types=[c_uint64, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(proof), err)
    err.throw_on_error()


def bbs_verify_blind_commitment_context_finish(handle: int) -> int:
    func = wrap_native_func(
        "bbs_verify_blind_commitment_context_finish",
        arg_types=[c_uint64, POINTER(ExternError)],
    )
    err = ExternError()
    result = func(handle, err)
    err.throw_on_error()
    return result


__all__ = [
    bbs_verify_blind_commitment_context_init,
    bbs_verify_blind_commitment_context_add_blinded,
    bbs_verify_blind_commitment_context_set_public_key,
    bbs_verify_blind_commitment_context_set_nonce_string,
    bbs_verify_blind_commitment_context_set_nonce_bytes,
    bbs_verify_blind_commitment_context_set_nonce_prehashed,
    bbs_verify_blind_commitment_context_set_proof,
    bbs_verify_blind_commitment_context_finish,
]