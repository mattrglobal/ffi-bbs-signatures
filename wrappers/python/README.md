# Hyperledger Ursa BBS Signatures Wrapper for Python
[![ci-python](https://github.com/animo/ffi-bbs-signatures/actions/workflows/ci-python.yml/badge.svg?branch=master)](https://github.com/animo/ffi-bbs-signatures/actions/workflows/ci-python.yml)
## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
  - [Prerequisites](#prerequisites)
  - [Installing](#installing)
    - [Using pip](#using_pip)
    - [Manually](#manually)
- [Running tests](#running_tests)

## About <a name = "about"></a>
This is a Python wrapper for Hyperledger Ursa's C callable BBS+ package. 

## Getting Started <a name = "getting_started"></a>

### Prerequisites
- Python
- Pip
- Optional:
  - If you'd like to run the python tests
    - Install [Pipenv](https://pypi.org/project/pipenv/)
  - If you'd like to build the BBS+ library yourself
    - Install [Rust](https://www.rust-lang.org/tools/install)
    - Follow installation instructions at https://github.com/mattrglobal/ffi-bbs-signatures

### Installing
#### Using pip
```sh
pip install ursa-bbs-signatures
```
#### Manually
1. Build the Rust BBS+ library as described [here](https://github.com/mattrglobal/ffi-bbs-signatures)
2. Place the resulting library (located in the `target/debug` directory) into the `wrappers/python/ursa_bbs_signatures` directory
3. Install the package into your environment by running `python -m pip install <PATH TO THIS REPOITORY>/wrappers/python`

### Running tests
1. Make sure you have [Pipenv](https://pypi.org/project/pipenv/) installed
2. This project uses `Pytest` for testing, so make sure to install it by running `pipenv install --dev` in the `wrappers/python` directory
3. Run the tests using `pipenv run test`