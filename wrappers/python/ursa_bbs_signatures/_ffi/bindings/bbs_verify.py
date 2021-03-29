from ctypes import POINTER, byref, c_char_p, c_ulong
import sys
from typing import Optional, Union
from ..ExternError import ExternError

from ..ffi_util import (
    FfiByteBuffer,
    encode_bytes,
    encode_str,
    wrap_native_func,
)


if sys.version_info >= (3, 8):
    from typing import TypedDict  # pylint: disable=no-name-in-module
else:
    from typing_extensions import TypedDict

# Binding functions
def bbs_verify_context_init() -> int:
    func = wrap_native_func(
        "bbs_verify_context_init", arg_types=[POINTER(ExternError)], return_type=c_ulong
    )
    err = ExternError()
    handle = func(byref(err))
    err.throw_on_error()
    return handle


def bbs_verify_context_add_message_string(handle: int, message: str) -> None:
    func = wrap_native_func(
        "bbs_verify_context_add_message_string",
        arg_types=[c_ulong, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_str(message), err)
    err.throw_on_error()


def bbs_verify_context_add_message_bytes(handle: int, message: bytes) -> None:
    func = wrap_native_func(
        "bbs_verify_context_add_message_string",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(message), err)
    err.throw_on_error()


def bbs_verify_context_add_message_prehashed(handle: int, message: bytes) -> None:

    func = wrap_native_func(
        "bbs_verify_context_add_message_prehashed",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(message), err)
    err.throw_on_error()


def bbs_verify_context_set_public_key(handle: int, public_key: bytes) -> None:
    func = wrap_native_func(
        "bbs_verify_context_set_public_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(public_key), err)
    err.throw_on_error()


def bbs_verify_context_set_signature(handle: int, signature: bytes) -> None:
    func = wrap_native_func(
        "bbs_verify_context_set_signature",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(signature), err)
    err.throw_on_error()


def bbs_verify_context_finish(handle: int) -> int:
    func = wrap_native_func(
        "bbs_verify_context_finish", arg_types=[c_ulong, POINTER(ExternError)]
    )
    err = ExternError()
    result = func(handle, err)
    err.throw_on_error()
    return result


__all__ = [
    bbs_verify_context_init,
    bbs_verify_context_add_message_string,
    bbs_verify_context_add_message_bytes,
    bbs_verify_context_add_message_prehashed,
    bbs_verify_context_set_public_key,
    bbs_verify_context_set_signature,
    bbs_verify_context_finish
]