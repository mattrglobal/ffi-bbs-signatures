# Install and setup the rust tool cbindgen to automate the generation of the c header file through
# parsing the ffi-bbs-signatures library code.

set -e

rustup install nightly
rustup default nightly
cargo install cargo-expand
cargo install --force cbindgen
cbindgen --config cbindgen.toml --crate ffi-bbs-signatures --output include/bbs.h
rustup default stable
