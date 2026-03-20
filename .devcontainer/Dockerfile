# Cosmian KMS — development container
# Base: NixOS/Nix image, inspired by shell.nix and nix/softhsm2.nix
FROM nixos/nix:latest

# Enable the new command-line interface and flakes support for convenience,
# and allow unfree packages (needed by some HSM drivers)
RUN mkdir -p /etc/nix && printf \
  'experimental-features = nix-command flakes\nallow-unfree = true\n' \
  >> /etc/nix/nix.conf

# nixos/nix:latest ships git-minimal which conflicts with full nixpkgs.git
# (both provide git-prompt.sh), so we remove it first.
# gcc (not clang) matches the compiler used in shell.nix and is required for
# the OpenSSL build.rs in crate/crypto which invokes `cc`/`make`.
RUN nix-env -e git-minimal || true
RUN nix-env -iA \
  nixpkgs.bash \
  nixpkgs.git \
  nixpkgs.curl \
  nixpkgs.pkg-config \
  nixpkgs.gcc \
  nixpkgs.gnumake \
  nixpkgs.cmake \
  nixpkgs.perl \
  nixpkgs.libtool \
  nixpkgs.autoconf \
  nixpkgs.automake \
  nixpkgs.openssl \
  nixpkgs.softhsm \
  nixpkgs.rustup \
  nixpkgs.glibc \
  nixpkgs.gnused \
  nixpkgs.zsh \
  nixpkgs.starship \
  && nix-collect-garbage -d

# The Rust toolchain is installed into a shared directory so that both root
# (during Docker build steps) and the dev user can use it without ownership
# issues.  chmod -R a+rX makes the tree world-readable/executable.
ENV RUSTUP_HOME=/opt/rust/rustup
ENV CARGO_HOME=/opt/rust/cargo

# Expose Nix-installed tools and the Rust toolchain to every user and to all
# subsequent RUN layers.  Putting /root/.nix-profile/bin first ensures the
# Nix-managed binaries shadow any system stubs.
# /home/dev/.nix-profile/bin is included so that packages installed by the dev
# user via nix-env (or created by nix-shell) appear on PATH without restarting.
ENV PATH="/home/dev/.nix-profile/bin:/root/.nix-profile/bin:/opt/rust/cargo/bin:/usr/local/bin:$PATH"

# Pin the Rust toolchain; rustup was installed via Nix above so its binary is
# correctly patched for the Nix store dynamic linker.
RUN rustup toolchain install 1.91.0 --component rustfmt --component clippy \
  && rustup default 1.91.0 \
  && chmod -R a+rwX /opt/rust

# Provide standard-path cc/c++ aliases so build scripts that invoke `cc`
# directly (notably OpenSSL's ./Configure and the `cc` Rust crate) find a
# compiler without requiring CC to be set in the environment.
RUN mkdir -p /usr/local/bin \
  && ln -sf /root/.nix-profile/bin/gcc  /usr/local/bin/cc \
  && ln -sf /root/.nix-profile/bin/g++ /usr/local/bin/c++

# ── Pre-built OpenSSL ──────────────────────────────────────────────────────
# Build OpenSSL 3.6.0 static (no-shared) once at image-build time so
# developers never wait for the 5-minute compile on first cargo build.
# Two variants mirror exactly what crate/crypto/build.rs would produce:
#   /opt/openssl/fips     — enable-fips    (default cargo build)
#   /opt/openssl/non-fips — enable-legacy  (cargo build --features non-fips)
# The static libs + headers are consumed by both crate/crypto/build.rs
# (which detects the paths and skips its own download) and by openssl-sys
# (which reads OPENSSL_DIR from the environment, set in devcontainer.json).
ENV OPENSSL_VERSION=3.6.0
RUN set -e \
  && case "$(uname -m)" in \
  aarch64) OSSL_TGT=linux-aarch64 ;; \
  x86_64)  OSSL_TGT=linux-x86_64  ;; \
  *)       OSSL_TGT="linux-$(uname -m)" ;; \
  esac \
  && JOBS=$(nproc) \
  && mkdir -p /tmp/ossl-work \
  && curl -fsSL \
  "https://package.cosmian.com/openssl/openssl-${OPENSSL_VERSION}.tar.gz" \
  -o /tmp/ossl-work/openssl.tar.gz \
  && cd /tmp/ossl-work && tar -xf openssl.tar.gz \
  && SRCDIR="/tmp/ossl-work/openssl-${OPENSSL_VERSION}" \
  # ---- FIPS variant (no-shared, enable-fips) → /opt/openssl/fips ----
  && cp -r "$SRCDIR" /tmp/ossl-fips \
  && cd /tmp/ossl-fips \
  && perl ./Configure no-shared enable-fips \
  --prefix=/opt/openssl/fips \
  --openssldir=/opt/openssl/fips/ssl \
  --libdir=lib \
  "$OSSL_TGT" \
  && make -j"$JOBS" \
  && make install_sw install_ssldirs install_fips \
  # Activate the FIPS provider in openssl.cnf:
  #  1. Enable the fips_sect inside [provider_sect]  (un-comment "# fips = fips_sect")
  #  2. Un-comment and absolutify the .include path for fipsmodule.cnf
  && sed -i \
  's|^# \(fips = fips_sect\)|\1|; s|^# \?\.include \+fipsmodule\.cnf|.include /opt/openssl/fips/ssl/fipsmodule.cnf|' \
  /opt/openssl/fips/ssl/openssl.cnf || true \
  # ---- non-FIPS variant (no-shared, enable-legacy) → /opt/openssl/non-fips ----
  && cp -r "$SRCDIR" /tmp/ossl-nonfips \
  && cd /tmp/ossl-nonfips \
  && perl ./Configure no-shared enable-legacy \
  --prefix=/opt/openssl/non-fips \
  --openssldir=/opt/openssl/non-fips/ssl \
  --libdir=lib \
  "$OSSL_TGT" \
  && make -j"$JOBS" \
  && make install_sw install_ssldirs \
  # ---- Permissions + cleanup ----
  && chmod -R a+rX /opt/openssl \
  && rm -rf /tmp/ossl-work /tmp/ossl-fips /tmp/ossl-nonfips

# ── VS Code Server compat ───────────────────────────────────────────────────
# VS Code's bundled node binary requires several pieces missing from standard
# filesystem paths on nixos/nix:latest:
#
#   1. /lib/ld-linux-aarch64.so.1 — ELF interpreter baked into node.
#   2. libstdc++.so.6 / libc.so.6 — runtime libraries (also inspected by
#      check-requirements.sh via `ldconfig -p`).
#   3. LD_LIBRARY_PATH — checked before the ld.so cache; belt-and-suspenders
#      so node finds its shared libraries regardless of cache path.
#   4. ldconfig wrapper — rebuilds the cache on every call so
#      check-requirements.sh always sees current entries.
RUN LIBSTDCXX=$(find /nix/store -maxdepth 6 -name "libstdc++.so.6.0.*" \
  ! -name "*.py" ! -path "*/debug/*" 2>/dev/null | head -1) \
  && LIBC=$(find /nix/store -maxdepth 6 -path "*glibc*/lib/libc.so.6" \
  ! -path "*/debug/*" 2>/dev/null | head -1) \
  && LDLINUX=$(find /nix/store -maxdepth 6 -path "*glibc*/lib/ld-linux-aarch64.so.1" \
  2>/dev/null | head -1) \
  && mkdir -p /usr/lib /lib /usr/local/bin /etc/ld.so.conf.d \
  && { [ -n "$LIBSTDCXX" ] \
  && cp -L "$LIBSTDCXX" /usr/lib/$(basename "$LIBSTDCXX") \
  && ln -sf /usr/lib/$(basename "$LIBSTDCXX") /usr/lib/libstdc++.so.6 \
  && cp -L "$LIBSTDCXX" /lib/$(basename "$LIBSTDCXX") \
  && ln -sf /lib/$(basename "$LIBSTDCXX") /lib/libstdc++.so.6 \
  || true; } \
  && { [ -n "$LIBC" ] \
  && cp -L "$LIBC" /usr/lib/libc.so.6 \
  && cp -L "$LIBC" /lib/libc.so.6 \
  || true; } \
  && { [ -n "$LDLINUX" ] && cp -L "$LDLINUX" /lib/ld-linux-aarch64.so.1 || true; } \
  && printf '/usr/lib\n/lib\n' > /etc/ld.so.conf.d/nix-compat.conf \
  && /root/.nix-profile/bin/ldconfig -C /etc/ld.so.cache /usr/lib /lib \
  && printf '#!/bin/sh\n/root/.nix-profile/bin/ldconfig -C /etc/ld.so.cache /usr/lib /lib 2>/dev/null\nexec /root/.nix-profile/bin/ldconfig -C /etc/ld.so.cache "$@"\n' \
  > /usr/local/bin/ldconfig \
  && chmod +x /usr/local/bin/ldconfig

# Expose the copied libraries so any unpatched glibc binary (including VS Code's
# node) finds them without relying on the cache alone.
ENV LD_LIBRARY_PATH=/lib:/usr/lib

# ── Non-root dev user ───────────────────────────────────────────────────────
# Create a 'dev' user that VS Code connects as (remoteUser in devcontainer.json).
# updateRemoteUserUID will adjust the UID/GID at container start to match the
# host user, so files created inside have correct ownership on the host.
# zsh is linked to a stable /usr/bin path so PAM / /etc/shells lookups work.
# nixos/nix manages /etc/{passwd,group} as Nix-store symlinks.  Installing
# nixpkgs.shadow creates additional symlink layers that push /etc/group past
# the kernel's ELOOP limit (8 levels), breaking groupadd/useradd.
# Workaround: read the content through the current chain, remove the symlink,
# write a plain writable file, then append our 'dev' entry.
RUN mkdir -p /usr/bin \
  && ln -sf /root/.nix-profile/bin/zsh /usr/bin/zsh \
  && touch /etc/shells \
  && printf '/usr/bin/zsh\n' >> /etc/shells \
  && { cat /etc/passwd 2>/dev/null \
  || printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n'; \
  } > /tmp/etc-passwd \
  && { cat /etc/group 2>/dev/null \
  || printf 'root:x:0:\nnobody:x:65534:\n'; \
  } > /tmp/etc-group \
  && rm -f /etc/passwd && mv /tmp/etc-passwd /etc/passwd \
  && rm -f /etc/group  && mv /tmp/etc-group  /etc/group \
  && printf 'dev:x:1000:1000::/home/dev:/usr/bin/zsh\n' >> /etc/passwd \
  && printf 'dev:x:1000:\n' >> /etc/group \
  && mkdir -p /home/dev \
  && chown 1000:1000 /home/dev && chmod 755 /home/dev \
  && mkdir -p /home/dev/.config/softhsm2/tokens \
  && printf 'directories.tokendir = /home/dev/.config/softhsm2/tokens\n' \
  > /home/dev/.config/softhsm2/softhsm2.conf \
  && printf 'eval "$(starship init zsh)"\n' > /home/dev/.zshrc \
  && chown -R 1000:1000 /home/dev \
  # Transfer the entire Nix store to the dev user so that nix-shell (and any
  # nix command) works without root privileges.  nixos/nix:latest uses
  # single-user Nix mode where the store owner can build derivations directly —
  # no nix-daemon is needed.  The RUN layers above completed all root-owned nix
  # operations, so it is safe to hand off ownership here.
  && chown -R 1000:1000 /nix

ENV WITH_HSM=1
ENV SOFTHSM2_CONF=/home/dev/.config/softhsm2/softhsm2.conf
