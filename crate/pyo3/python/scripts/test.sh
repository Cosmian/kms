#!/bin/bash
set -eux

cd "$(dirname "$0")/../.."

# Setup python virtual environment
venv_dir="$(pwd)/target/venv"
rm -rf "$venv_dir"
mkdir -p "$venv_dir"
python3 -m venv "$venv_dir"

export PATH="$venv_dir/bin:$PATH"

pip install -r python/requirements.txt

rm -f ../../target/wheels/*.whl
maturin build --release
pip install --force-reinstall ../../target/wheels/*.whl

# Test typing
mypy python/scripts/test_kms_covercrypt.py
mypy python/scripts/test_kms.py
# Unit tests (requires python3.8 or newer)
python3 python/scripts/test_kms_covercrypt.py
python3 python/scripts/test_kms.py
