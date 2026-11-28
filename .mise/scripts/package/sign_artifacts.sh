#!/usr/bin/env bash
# Detached-sign (GPG, ASCII-armored) every package found under <dir>.
# Usage: sign_artifacts.sh <dir>
#
# Runs only in the isolated `sign` jobs of the packaging workflows: the build jobs execute third-party
# code (Nix, cargo) and hold no signing secret. The key must already be imported into the GPG keyring
# (.github/actions/import-gpg-key) and GPG_SIGNING_KEY_PASSPHRASE must be set.

set -euo pipefail

if [ $# -ne 1 ] || [ ! -d "$1" ]; then
  echo "Usage: $0 <dir>" >&2
  exit 2
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
export REPO_ROOT # read by sign_packages

# package_common.sh parses its own arguments when executed, so extract the function only
# (same approach as package_dmg.sh).
_sign_tmp=$(mktemp)
sed -n '/^sign_packages()/,/^}/p' "$SCRIPT_DIR/package_common.sh" >"$_sign_tmp"
# shellcheck disable=SC1090
source "$_sign_tmp"
rm -f "$_sign_tmp"

export REQUIRE_SIGNING=1

count=0
while IFS= read -r -d '' pkg; do
  sign_packages "$pkg"
  count=$((count + 1))
done < <(find "$1" -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.dmg' -o -name '*.zip' -o -name '*.apk' \) -print0)

if [ "$count" -eq 0 ]; then
  echo "ERROR: no package to sign under $1" >&2
  exit 1
fi
echo "Signed $count package(s) under $1"
