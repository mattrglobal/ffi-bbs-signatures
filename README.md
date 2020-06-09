An FFI Wrapper around Hyperledger Ursa's BBS+ implementation.

All that is needed to use the library is the following two artifacts: bbs.h and the native library for OS platforms:

- Mac OS X: libbbs.dylib
- Windows: libbbs.dll
- Linux/Android: libbbs.so
- iOS: libbbs.a

## Building from source
This library is written in Rust and exposed through the FFI wrapper.
To build it for a specific system, install Rust and run `make`.
To install rust see [here](https://www.rust-lang.org/tools/install)