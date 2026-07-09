#!/bin/bash

packages=(
  apt-utils
  ca-certificates
  ccache
  clang-19
  clang-tools-19
  clang-tidy-19
  cmake
  curl
  dialog
  g++-15
  gcc-15
  gdb
  git
  gnupg
  libclang-common-19-dev
  libclang-rt-19-dev
  llvm-19-dev
  make
  mold
  ninja-build
  pkg-config
  python-is-python3
  python3-pytest
  ripgrep
  software-properties-common
  valgrind
  wget
)

apt-get install -y --no-install-recommends "${packages[@]}"

# Install sccache (supports GitHub Actions cache backend for persistent
# compilation caching across CI runs on ephemeral runners).
SCCACHE_VERSION=0.9.1
curl -fsSL "https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
  | tar xz -C /usr/local/bin --strip-components=1 "sccache-v${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache"
