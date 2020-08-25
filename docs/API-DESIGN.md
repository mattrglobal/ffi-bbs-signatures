## API Design

Each operation uses a context object to that stores the current state until the finish operation is called,
unless the operation is simple enough to perform with a single function call. Please take note:

1. This library avoids throwing panics over the FFI (which is undefined behavior)
1. This library translates rust errors (and panics) into errors that the caller on the other side of the FFI is able to handle.
1. Uses structures instead of basic types to minimize the number of parameters passed to functions.
    1. For example, ByteBuffer and ExternError.
1. Most functions return 0 if successful and non-zero if an error occurs. 
1. When functions create values like `bls_generate_key`, the caller is responsible for freeing the values returned
as Rust no longer guarantees ownership and cannot be responsible for its management.

Examples can be found in [bbs_test](../tests/bbs_test.c)
