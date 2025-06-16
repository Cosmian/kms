#!/bin/bash

# Simple test to verify error detection
cd /Users/bgrieder/projects/kms
source .venv/bin/activate

echo "Testing destroy operation..."
output=$(python scripts/pykmip_client.py --configuration scripts/pykmip.conf --operation destroy 2>&1)

echo "=== OUTPUT ==="
echo "$output"
echo "=============="

if echo "$output" | grep -q '"status": "error"'; then
    echo "✅ CORRECTLY DETECTED ERROR STATUS"
else
    echo "❌ FAILED TO DETECT ERROR STATUS"
fi

if echo "$output" | grep -q '"status": "success"'; then
    echo "❌ INCORRECTLY SHOWS SUCCESS"
else
    echo "✅ CORRECTLY DOES NOT SHOW SUCCESS"
fi
