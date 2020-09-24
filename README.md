# BBS Signature FFI Wrapper

This repository is home to a foreign function interface (FFI) wrapper around the rust based [bbs crate](https://crates.io/crates/bbs) maintained by the [Hyperledger Ursa project](https://github.com/hyperledger/ursa).

[BBS+ Signatures](https://github.com/mattrglobal/bbs-signatures) are a digital signature algorithm originally born from
the work on [Short group signatures](https://crypto.stanford.edu/~xb/crypto04a/groupsigs.pdf) by Boneh, Boyen, and
Shachum which was later improved on in
[Constant-Size Dynamic k-TAA](http://web.cs.iastate.edu/~wzhang/teach-552/ReadingList/552-14.pdf) as BBS+ and touched on
again in section 4.3 in
[Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited ](https://www.researchgate.net/publication/306347781_Anonymous_Attestation_Using_the_Strong_Diffie_Hellman_Assumption_Revisited).

[BBS+ Signatures](https://github.com/mattrglobal/bbs-signatures) require a
[pairing-friendly curve](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03), this library includes
support for [BLS12-381](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03#section-2.4).

[BBS+ Signatures](https://github.com/mattrglobal/bbs-signatures) allow for multi-message signing whilst producing a
single output signature. With a BBS signature, a [proof of knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge)
based proof can be produced where only some of the originally signed messages are revealed at the discretion of the
prover.

## Supported Environments

Every release of this repository publishes a new [github release](https://github.com/mattrglobal/ffi-bbs-signatures/releases/tag/v0.1.0) including publishing the platform specific artifacts required to run the library in different environments. See the [release process](./docs/RELEASE.md) for
more details on this process

# Getting started

This repository makes use of [Yarn](https://yarnpkg.com/) to manage the dependencies related to the development environment

To install the development dependencies run

```
yarn install --frozen-lockfile
```

To build the library for all available platforms run

```
yarn build
```

To build a particular wrapper run

```
yarn wrappers:<name-of-wrapper>:build
```

Where the available wrappers are

- obj-c => Objective-C wrapper

**Note** The dotnet wrapper has its own build process documented [here](./wrappers/dotnet/README.md)
