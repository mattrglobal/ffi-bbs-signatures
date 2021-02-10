# Objective C Wrapper for bbs-signatures

# Building

From the root of the repository after setting up the [development toolchain](../../README.md) run

```
yarn wrapper:obj-c:build
```

To update Rust static library run

```
yarn wrapper:obj-c:update-binary
```

It will generate `libbbs.a` binary under `libraries/libbbs.a` for Objective-C wrapper to consume.

# Supported Architectures

Due to rust ending support for 32bit targets this pod only works with `x86_64` and `arm64` see [here](https://blog.rust-lang.org/2020/01/03/reducing-support-for-32-bit-apple-targets.html) for more details.
