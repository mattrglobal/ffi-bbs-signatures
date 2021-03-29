from ctypes import POINTER, byref, c_uint
from logging import error
import sys
from typing import Optional, Union
from ..ExternError import ExternError

from ..ffi_util import (
    FfiByteBuffer,
    encode_bytes,
    wrap_native_func,
)

if sys.version_info >= (3, 8):
    from typing import TypedDict  # pylint: disable=no-name-in-module
else:
    from typing_extensions import TypedDict


class GenerateKeyReturnType(TypedDict):
    public_key: bytes
    secret_key: bytes


class GenerateBlindedKeyReturnType(TypedDict):
    public_key: bytes
    secret_key: bytes
    blinding_factor: bytes


def bls_secret_key_size() -> int:
    func = wrap_native_func("bls_secret_key_size")
    return func()


def bls_public_key_g2_size() -> int:
    func = wrap_native_func("bls_public_key_g2_size")
    return func()


def blinding_factor_size() -> int:
    func = wrap_native_func("blinding_factor_size")
    return func()


def bls_public_key_g1_size() -> int:
    func = wrap_native_func("bls_public_key_g1_size")
    return func()


def bls_generate_g1_key(seed: Optional[Union[str, bytes]]) -> GenerateKeyReturnType:
    func = wrap_native_func(
        "bls_generate_g1_key",
        arg_types=[
            FfiByteBuffer,
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(ExternError),
        ],
    )
    pub, sec, err = FfiByteBuffer(), FfiByteBuffer(), ExternError()
    func(encode_bytes(seed), byref(pub), byref(sec), byref(err))

    err.throw_on_error()

    return {
        "public_key": bytes(pub),
        "secret_key": bytes(sec),
    }


def bls_generate_g2_key(seed: Optional[Union[str, bytes]]) -> GenerateKeyReturnType:
    func = wrap_native_func(
        "bls_generate_g2_key",
        arg_types=[
            FfiByteBuffer,
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(ExternError),
        ],
    )
    pub, sec, err = FfiByteBuffer(), FfiByteBuffer(), ExternError()
    func(encode_bytes(seed), byref(pub), byref(sec), byref(err))

    err.throw_on_error()

    return {
        "public_key": bytes(pub),
        "secret_key": bytes(sec),
    }


def bls_generate_blinded_g1_key(
    seed: Optional[Union[str, bytes]]
) -> GenerateBlindedKeyReturnType:
    func = wrap_native_func(
        "bls_generate_blinded_g1_key",
        arg_types=[
            FfiByteBuffer,
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(ExternError),
        ],
    )

    pub, sec, blind_fact, err = (
        FfiByteBuffer(),
        FfiByteBuffer(),
        FfiByteBuffer(),
        ExternError(),
    )
    func(encode_bytes(seed), byref(pub), byref(sec), byref(blind_fact), byref(err))

    err.throw_on_error()

    return {
        "public_key": bytes(pub),
        "secret_key": bytes(sec),
        "blinding_factor": bytes(blind_fact),
    }


def bls_generate_blinded_g2_key(
    seed: Optional[Union[str, bytes]]
) -> GenerateBlindedKeyReturnType:
    func = wrap_native_func(
        "bls_generate_blinded_g2_key",
        arg_types=[
            FfiByteBuffer,
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(FfiByteBuffer),
            POINTER(ExternError),
        ],
    )

    pub, sec, blind_fact, err = (
        FfiByteBuffer(),
        FfiByteBuffer(),
        FfiByteBuffer(),
        ExternError(),
    )
    func(encode_bytes(seed), byref(pub), byref(sec), byref(blind_fact), byref(err))

    err.throw_on_error()

    return {
        "public_key": bytes(pub),
        "secret_key": bytes(sec),
        "blinding_factor": bytes(blind_fact)
    }


def bls_get_public_key(secret_key: bytes) -> bytes:
    func = wrap_native_func(
        "bls_get_public_key",
        arg_types=[FfiByteBuffer, POINTER(FfiByteBuffer), POINTER(ExternError)],
    )
    pub, err = FfiByteBuffer(), ExternError()
    func(encode_bytes(secret_key), byref(pub), byref(err))

    err.throw_on_error()

    return bytes(pub)


def bls_secret_key_to_bbs_key(secret: bytes, message_count: int) -> bytes:
    func = wrap_native_func(
        "bls_secret_key_to_bbs_key",
        arg_types=[FfiByteBuffer, c_uint, POINTER(FfiByteBuffer), POINTER(ExternError)],
    )
    pub, err = FfiByteBuffer(), ExternError()

    func(encode_bytes(secret), message_count, byref(pub), byref(err))

    err.throw_on_error()

    return bytes(pub)


def bls_public_key_to_bbs_key(d_public_key: bytes, message_count: int) -> bytes:
    func = wrap_native_func(
        "bls_public_key_to_bbs_key",
        arg_types=[FfiByteBuffer, c_uint, POINTER(FfiByteBuffer), POINTER(ExternError)],
    )
    pub, err = FfiByteBuffer(), ExternError()
    func(encode_bytes(d_public_key), message_count, byref(pub), byref(err))
    err.throw_on_error()
    return bytes(pub)

__all__ = [
    bls_secret_key_size,
    bls_public_key_g2_size,
    blinding_factor_size,
    bls_public_key_g1_size,
    bls_generate_g1_key,
    bls_generate_g2_key,
    bls_generate_blinded_g1_key,
    bls_generate_blinded_g2_key,
    bls_get_public_key,
    bls_secret_key_to_bbs_key,
    bls_public_key_to_bbs_key
]