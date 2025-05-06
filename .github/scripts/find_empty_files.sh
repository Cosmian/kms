#!/bin/bash

set -ex

# Find all regular files that are empty (size 0)
find . -not -path "./*.cargo_check/**" -not -path "./**target/**" -not -path "./*env/lib/*" -not -path "./*node_modules/**" -type f -empty -print
