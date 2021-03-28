import os
import sys
import logging

from ctypes import (
    Array,
    CDLL,
    POINTER,
    Structure,
    c_char_p,
    c_int64,
    c_ubyte,
    c_void_p,
    string_at,
)
from ctypes.util import find_library
from typing import Any, Callable, List, Optional, Union

from .FfiException import FfiException

LOGGER = logging.getLogger(__name__)
LOG_LEVELS = {
    1: logging.ERROR,
    2: logging.WARNING,
    3: logging.INFO,
    4: logging.DEBUG,
}

# FIXME: this is a double declaration (see setup.py)
PACKAGE_NAME = "ursa_bbs_signatures"

LIB: CDLL = None

def wrap_native_func(
    function_name: str,
    *,
    arg_types: Optional[List[Any]] = None,
    return_type: Optional[Any] = None,
) -> Callable:
    lib_func = getattr(get_library(), function_name)
    if arg_types:
        lib_func.argtypes = arg_types
    if return_type:
        lib_func.restype = return_type

    return lib_func


def get_library() -> CDLL:
    """Return the CDLL instance, loading it if necessary."""
    global LIB
    if LIB is None:
        LIB = _load_library("libbbs")
    return LIB


def _load_library(lib_name: str):
    """Load the CDLL library."""
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")

        lib_path = os.path.join(
            os.path.abspath("."), PACKAGE_NAME, f"{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        LOGGER.debug("Unknown platform for shared library")
    except OSError:
        LOGGER.warning("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        raise FfiException(f"Library not found in path: {lib_path}")
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise FfiException(f"Error loading library: {lib_path}") from e


class ByteBuffer(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("len", c_int64),
        ("value", c_void_p),
    ]

    @property
    def raw(self) -> Array:
        # print(self.len, self.value)
        ret = (c_ubyte * self.len).from_address(self.value)
        setattr(ret, "_ref_", self)  # ensure buffer is not dropped
        return ret

    def __bytes__(self) -> bytes:
        return bytes(self.raw)

    def __repr__(self) -> str:
        """Format byte buffer as a string."""
        return repr(bytes(self))

    def __del__(self):
        """Call the byte buffer destructor when this instance is released."""
        get_library().bbs_byte_buffer_free(self)


class FfiByteBuffer(Structure):
    """A byte buffer allocated by python."""

    _fields_ = [
        ("len", c_int64),
        ("value", POINTER(c_ubyte)),
    ]

    @property
    def raw(self) -> bytes:
        # print(self.len, self.value)
        ret = string_at(self.value, self.len)
        # setattr(ret, "_ref_", self)  # ensure buffer is not dropped
        return ret

    def __bytes__(self) -> bytes:
        return bytes(self.raw)


def decode_str(value: c_char_p) -> str:
    return value.decode("utf-8")


def encode_str(arg: Optional[Union[str, bytes]]) -> c_char_p:
    """
    Encode an optional input argument as a string.
    Returns: None if the argument is None, otherwise the value encoded utf-8.
    """
    if arg is None:
        return c_char_p()
    if isinstance(arg, str):
        return c_char_p(arg.encode("utf-8"))
    return c_char_p(arg)


def encode_bytes(arg: Optional[Union[str, bytes]]) -> FfiByteBuffer:
    buf = FfiByteBuffer()
    if isinstance(arg, memoryview):
        buf.len = arg.nbytes
        if arg.contiguous and not arg.readonly:
            buf.value = (c_ubyte * buf.len).from_buffer(arg.obj)
        else:
            buf.value = (c_ubyte * buf.len).from_buffer_copy(arg.obj)
    elif isinstance(arg, bytearray):
        buf.len = len(arg)
        buf.value = (c_ubyte * buf.len).from_buffer(arg)
    elif arg is not None:
        if isinstance(arg, str):
            arg = arg.encode("utf-8")
        buf.len = len(arg)
        buf.value = (c_ubyte * buf.len).from_buffer_copy(arg)
    return buf