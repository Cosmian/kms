# Cosmian KMS — packaging container
# Supports only the four nix-based package builds:
#   bash .github/scripts/nix.sh --variant non-fips --link static  package
#   bash .github/scripts/nix.sh --variant non-fips --link dynamic package
#   bash .github/scripts/nix.sh --variant fips     --link static  package
#   bash .github/scripts/nix.sh --variant fips     --link dynamic package
FROM nixos/nix:latest

# Enable the new command-line interface and allow unfree packages.
RUN mkdir -p /etc/nix && printf \
  'experimental-features = nix-command flakes\nallow-unfree = true\n' \
  >> /etc/nix/nix.conf

# nixos/nix:latest ships git-minimal which conflicts with full nixpkgs.git
# (both provide git-prompt.sh), so we remove it first.
RUN nix-env -e git-minimal || true
RUN nix-env -iA \
  nixpkgs.bash \
  nixpkgs.gawk \
  nixpkgs.gnused \
  nixpkgs.git \
  && nix-collect-garbage -d

# Pre-warm Nix store with large downloads that would otherwise happen deep into
# the 2+ hour build, where macOS Docker VM DNS becomes unreliable.
# These layers are Docker-cached (they precede COPY) and survive subsequent builds.
RUN nix-instantiate --eval -E \
  'builtins.fetchTarball "https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz"' \
  >/dev/null
RUN nix-instantiate --eval -E \
  'builtins.fetchTarball { url = "https://package.cosmian.com/nixpkgs/nixos-19.03.tar.gz"; sha256 = "sha256-i1XCn9rKuLjvCdu2UeXKzGLF6IuQePQKFt4hEKRU5oc="; }' \
  >/dev/null

WORKDIR /tmp/kms-src
COPY . /tmp/kms-src

RUN bash .github/scripts/nix.sh --variant non-fips --link static  package
RUN bash .github/scripts/nix.sh --variant non-fips --link dynamic package
RUN bash .github/scripts/nix.sh --variant fips     --link static  package
RUN bash .github/scripts/nix.sh --variant fips     --link dynamic package
