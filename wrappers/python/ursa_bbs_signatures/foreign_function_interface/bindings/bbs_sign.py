import sys
from ctypes import POINTER, byref, c_char_p, c_double, c_int, c_long, c_uint, c_ulong
from email import message
from typing import Optional, Union
from ursa_bbs_signatures.foreign_function_interface.ExternError import ExternError

from ursa_bbs_signatures.foreign_function_interface.ffi_util import (
    FfiByteBuffer,
    encode_bytes,
    encode_str,
    wrap_native_func,
)


if sys.version_info >= (3, 8):
    from typing import TypedDict  # pylint: disable=no-name-in-module
else:
    from typing_extensions import TypedDict


def bbs_signature_size() -> int:
    func = wrap_native_func("bbs_signature_size", return_type=c_uint)
    return func()


def bbs_sign_context_init() -> int:
    func = wrap_native_func(
        "bbs_sign_context_init", arg_types=[POINTER(ExternError)], return_type=c_long
    )
    err = ExternError()
    handle = func(byref(err))

    err.throw_on_error()

    return handle


def bbs_sign_context_finish(handle: int) -> FfiByteBuffer:
    func = wrap_native_func(
        "bbs_sign_context_finish",
        arg_types=[c_ulong, POINTER(FfiByteBuffer), POINTER(ExternError)]
    )
    sig, err = FfiByteBuffer(), ExternError()
    func(handle, byref(sig), byref(err))

    err.throw_on_error()

    return sig


def bbs_sign_context_add_message_string(handle: int, message: str) -> None:
    func = wrap_native_func(
        "bbs_sign_context_add_message_string",
        arg_types=[c_ulong, c_char_p, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_str(message), byref(err))

    err.throw_on_error()


def bbs_sign_context_add_message_bytes(handle: int, message: Union[str, bytes]) -> None:
    func = wrap_native_func(
        "bbs_sign_context_add_message_bytes",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(message), byref(err))

    err.throw_on_error()


def bbs_sign_context_add_message_prehashed(
    handle: int, message: Union[str, bytes]
) -> None:
    func = wrap_native_func(
        "bbs_sign_context_add_message_prehashed",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(message), byref(err))
    err.throw_on_error()


def bbs_sign_context_set_public_key(handle: int, public_key: Union[str, bytes]) -> None:
    func = wrap_native_func(
        "bbs_sign_context_set_public_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(public_key), byref(err))
    err.throw_on_error()


def bbs_sign_context_set_secret_key(handle: int, secret_key: Union[str, bytes]) -> None:
    func = wrap_native_func(
        "bbs_sign_context_set_secret_key",
        arg_types=[c_ulong, FfiByteBuffer, POINTER(ExternError)],
    )
    err = ExternError()
    func(handle, encode_bytes(secret_key), byref(err))
    err.throw_on_error()
