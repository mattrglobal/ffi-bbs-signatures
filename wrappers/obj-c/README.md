# Objective C Wrapper for bbs-signatures

# Building

From the root of the repository run

```
pod lib lint
```

If you encounter an error run with the `--verbose` flag

# Supported Architectures

Due to rust ending support for 32bit targets this pod only works with `x86_64` and `arm64` see [here](https://blog.rust-lang.org/2020/01/03/reducing-support-for-32-bit-apple-targets.html) for more details.
