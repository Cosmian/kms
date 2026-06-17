#!/bin/bash
# Activate PyKMIP virtual environment
cd "$(dirname "$0")/.." || exit
source .venv/bin/activate
echo "PyKMIP virtual environment activated"
echo "Run 'deactivate' to exit the virtual environment"
