#!/usr/bin/env bash
# Works around the expired TLS certificate of mirror.easyname.at, the host the pinned
# nixpkgs downloads several GNU "nongnu" sources from (acl, attr, lzip, ...). Without it,
# the musl cross toolchain build fails with "SSL certificate OpenSSL verify result:
# certificate has expired (10)".
#
# Fixed-output derivations are content-addressed: if their output path is already valid in
# the store, Nix does not run (nor re-download) them. So, for every fixed-output
# derivation in the closure of the given attributes whose URL points at the expired
# mirror, fetch the identical file from upstream Savannah and add it to the store. The
# resulting store path is asserted to be the one the derivation expects, so a content
# mismatch fails loudly instead of being silently ignored.
#
# Usage: seed_expired_nix_mirror_sources.sh <default.nix attribute>...
# Remove once the pinned nixpkgs no longer references mirror.easyname.at.
set -euo pipefail

# URL prefixes served by the expired mirror (directly, or through nixpkgs' `mirror://savannah/`
# alias, whose first entry is that host) -> path below UPSTREAM.
BAD_PREFIXES=("https://mirror.easyname.at/nongnu/" "mirror://savannah/")
UPSTREAM="https://download.savannah.nongnu.org/releases/"

[ "$#" -gt 0 ] || {
  echo "Usage: $0 <default.nix attribute>..." >&2
  exit 2
}

drvs=()
for attr in "$@"; do
  drvs+=("$(nix-instantiate default.nix -A "$attr" 2>/dev/null)")
done

# One "<drv path>\t<url>" line per flat sha256 fixed-output derivation using the bad mirror.
nix derivation show --recursive "${drvs[@]}" | python3 -c '
import json, sys

prefixes = tuple(sys.argv[1:])
data = json.load(sys.stdin)
# Newer Nix wraps the derivations: {"version": N, "derivations": {...}}.
for name, drv in data.get("derivations", data).items():
    if not isinstance(drv, dict):
        continue
    out = drv.get("outputs", {}).get("out", {})
    if out.get("hash") is None:
        continue
    env = drv.get("env", {})
    for url in (env.get("urls") or env.get("url") or "").split():
        if url.startswith(prefixes):
            if out.get("hashAlgo") != "sha256" or out.get("method") != "flat":
                sys.exit(f"unsupported fixed-output mode for {name}: {out}")
            print(f"/nix/store/{name}\t{url}")
' "${BAD_PREFIXES[@]}" | while IFS=$'\t' read -r drv url; do
  rel="$url"
  for prefix in "${BAD_PREFIXES[@]}"; do rel="${rel#"$prefix"}"; done
  expected="$(nix-store --query --outputs "$drv")"
  file="$(mktemp -d)/$(basename "$rel")"
  curl --retry 5 --retry-delay 5 --retry-all-errors -fsSL -o "$file" "${UPSTREAM}${rel}"
  actual="$(nix-store --add-fixed sha256 "$file")"
  if [ "$actual" != "$expected" ]; then
    echo "ERROR: ${UPSTREAM}${rel} produced $actual, expected $expected" >&2
    exit 1
  fi
  echo "Seeded $actual"
done
