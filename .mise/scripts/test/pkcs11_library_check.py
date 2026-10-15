#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check that a shared library exposes a usable PKCS#11 entry point."""

from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import sys


CK_RV = ctypes.c_ulong
CKR_OK = 0


def check_library(module_path: Path) -> None:
    """Load a PKCS#11 library and call its function-list discovery entry point."""
    if not module_path.is_file():
        raise RuntimeError(f"PKCS#11 library does not exist: {module_path}")

    try:
        library = ctypes.CDLL(str(module_path))
    except OSError as error:
        raise RuntimeError(
            f"could not load PKCS#11 library {module_path}: {error}"
        ) from error

    try:
        get_function_list = library.C_GetFunctionList
    except AttributeError as error:
        raise RuntimeError(
            f"PKCS#11 library has no C_GetFunctionList: {module_path}"
        ) from error

    get_function_list.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    get_function_list.restype = CK_RV
    function_list = ctypes.c_void_p()
    return_code = get_function_list(ctypes.byref(function_list))
    if return_code != CKR_OK:
        raise RuntimeError(
            f"C_GetFunctionList failed with return code 0x{return_code:x}"
        )
    if not function_list.value:
        raise RuntimeError('C_GetFunctionList returned a null function-list pointer')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--module', type=Path, required=True, help='PKCS#11 shared library'
    )
    args = parser.parse_args()

    try:
        check_library(args.module.expanduser().resolve())
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"PKCS#11 library is loadable: {args.module}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
