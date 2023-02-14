#!/bin/bash
set -eux

cd "$(dirname "$0")/../.."

pip install -r python/requirements.txt

rm -f ../../target/wheels/*.whl
maturin build --release
pip install --force-reinstall ../../target/wheels/*.whl

# Test typing
mypy python/scripts/test_kms.py
# Unit tests (requires python3.8 or newer)
python3 python/scripts/test_kms.py
