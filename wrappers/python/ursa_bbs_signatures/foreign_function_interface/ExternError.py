from ctypes import Structure, c_char_p, c_int32
from typing import Optional

from .ffi_util import decode_str
from .FfiException import FfiException


class ExternError(Structure):
    _fields_ = [("code", c_int32), ("message", c_char_p)]

    def __repr__(self) -> str:
        out = f"ExternError -> code: {self.code}"
        if self.message:
            out += f", message: {decode_str(self.message)}"
        return out

    def throw_on_error(self, extra_message: Optional[str] = None) -> None:
        if self.code:
            ffi_message = repr(decode_str(self.message))
            message = (
                f"{extra_message}: {ffi_message}" if extra_message else ffi_message
            )
            raise FfiException(message)