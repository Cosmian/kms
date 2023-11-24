# Cosmian KMS Python

This library is part of [CloudProof Python](https://github.com/Cosmian/cloudproof_python).

## Building and testing

You need to have `maturin` installed. To install it, run:

```bash
python3 -m pip install maturin
```

To build the Python interface, run:

```bash
maturin build --release
```

__Note__: when a new function or class is added to the PyO3 interface, its signature needs to be added to [`__init__.pyi`](python/cosmian_kms/__init__.pyi).

To run tests on the Python interface, run:

```bash
./python/scripts/test.sh
```
