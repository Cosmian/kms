#!/bin/bash
set -eux

cd "$(dirname "$0")/../.."

pip install -r python/requirements.txt
rm -f ../../target/wheels/*.whl

maturin build --release
pip install --force-reinstall ../../target/wheels/*.whl

# Clone and build CoverCrypt
rm -rf /tmp/cover_crypt
git clone --branch develop https://github.com/Cosmian/cover_crypt.git /tmp/cover_crypt
pushd /tmp/cover_crypt
git checkout edb5c8e6
maturin build --release --features python
pip install --force-reinstall target/wheels/*.whl
popd

# Test typing
mypy python/scripts/test_kms.py
# Unit tests (requires python3.8 or newer)
python3 python/scripts/test_kms.py
