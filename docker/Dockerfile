# syntax=docker/dockerfile:1-labs

FROM ubuntu:26.04 AS base

COPY scripts/ubuntu-build/ /opt

RUN apt-get update && \
    apt-get upgrade -y && \
    /opt/install-boost.sh && \
    /opt/install-tools.sh && \
    /opt/install-deps.sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    rm -rf /opt

FROM base AS base_rust

RUN apt-get update && \
    apt-get install -y gcc rustup && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    rm -rf /opt

RUN rustup toolchain install 1.91.1 --profile minimal --component clippy
RUN rustup toolchain install nightly-2025-12-09 --profile minimal --component rustfmt
RUN RUSTFLAGS="-C linker=gcc-15" cargo install cargo-shear@1.9.1

FROM base AS build

COPY . src

ARG CC
ARG CXX
ARG CMAKE_BUILD_TYPE
ARG TOOLCHAIN
ARG GIT_COMMIT_HASH

ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH

RUN cd src && CC=${CC:?} CXX=${CXX:?} CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:?} CMAKE_TOOLCHAIN_FILE=category/core/toolchains/${TOOLCHAIN:?}.cmake ./scripts/configure.sh

# Clean up to save disk space before the heavy build
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Build with sccache using the GitHub Actions cache backend (ghac v2).
# On a warm cache only changed translation units recompile.
#
# Three variables are all required, and each fails differently if missing:
#
#   ACTIONS_RESULTS_URL       GitHub retired the v1 cache service that
#                             ACTIONS_CACHE_URL points at; it now 404s.
#   ACTIONS_CACHE_SERVICE_V2  sccache's opendal ghac backend selects v1 vs v2
#                             solely on this being non-empty. Without it, it
#                             speaks v1 at the v2 URL: reads degrade to clean
#                             misses, but every write fails.
#   ACTIONS_RUNTIME_TOKEN     auth for both.
#
# sccache treats an unusable cache as a warning, not an error, so a broken
# cache yields a green build that silently recompiles everything. Assert on
# the stats instead of trusting the exit code.
RUN --mount=type=secret,id=actions_results_url \
    --mount=type=secret,id=actions_runtime_token \
    --mount=type=secret,id=actions_cache_service_v2 \
    cd src && \
    if [ -s /run/secrets/actions_results_url ] && [ -s /run/secrets/actions_runtime_token ]; then \
      export SCCACHE_GHA_ENABLED=true; \
      export ACTIONS_RESULTS_URL=$(cat /run/secrets/actions_results_url); \
      export ACTIONS_RUNTIME_TOKEN=$(cat /run/secrets/actions_runtime_token); \
      export ACTIONS_CACHE_SERVICE_V2=$(cat /run/secrets/actions_cache_service_v2); \
      sccache --start-server; \
      ./scripts/build.sh; \
      sccache --show-stats; \
      if [ "$(sccache --show-stats | awk '/^Cache write errors/ {print $NF}')" != "0" ]; then \
        echo "ERROR: sccache failed to write to the GHA cache; refusing to ship an uncached build."; \
        exit 1; \
      fi; \
    else \
      echo "No Actions cache credentials; building without sccache."; \
      cmake -B build -DCMAKE_C_COMPILER_LAUNCHER= -DCMAKE_CXX_COMPILER_LAUNCHER=; \
      ./scripts/build.sh; \
    fi

# Tests are a leaf stage: the `runner` image copies binaries from `build` and
# never pulls this in, so publishing does not pay for the (~30 min) suite that
# the Docker workflow's build_and_test matrix already runs.
FROM build AS build_and_test

ARG CC
ARG CXX
ARG CMAKE_BUILD_TYPE

# security=insecure for tests which use io_uring
RUN --security=insecure cd src && CC=${CC:?} CXX=${CXX:?} CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:?} ./scripts/test.sh

FROM base AS build_and_test_vm

COPY . src

ARG CC
ARG CXX
ARG CMAKE_BUILD_TYPE
ARG TOOLCHAIN

RUN cd src && CC=${CC:?} CXX=${CXX:?} CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:?} CMAKE_TOOLCHAIN_FILE=category/core/toolchains/${TOOLCHAIN:?}.cmake ./scripts/configure.sh
RUN cd src && cmake build -DMONAD_COMPILER_TESTING=On

RUN --mount=type=secret,id=actions_results_url \
    --mount=type=secret,id=actions_runtime_token \
    --mount=type=secret,id=actions_cache_service_v2 \
    cd src && \
    if [ -s /run/secrets/actions_results_url ] && [ -s /run/secrets/actions_runtime_token ]; then \
      export SCCACHE_GHA_ENABLED=true; \
      export ACTIONS_RESULTS_URL=$(cat /run/secrets/actions_results_url); \
      export ACTIONS_RUNTIME_TOKEN=$(cat /run/secrets/actions_runtime_token); \
      export ACTIONS_CACHE_SERVICE_V2=$(cat /run/secrets/actions_cache_service_v2); \
      sccache --start-server; \
    else \
      echo "No Actions cache credentials; building without sccache."; \
      cmake -B build -DCMAKE_C_COMPILER_LAUNCHER= -DCMAKE_CXX_COMPILER_LAUNCHER=; \
    fi && \
    ./scripts/vm/build-tests.sh && \
    { sccache --show-stats || true; }
RUN cd src && ./scripts/vm/test.sh

FROM base_rust AS build_and_test_rust

COPY . src

ARG CC
ARG CXX
ENV TRIEDB_TARGET="triedb_driver"

RUN cd src/rust && cargo update --workspace --locked
RUN cd src/rust && cargo +nightly-2025-12-09 fmt --all --check
RUN --mount=type=secret,id=actions_results_url \
    --mount=type=secret,id=actions_runtime_token \
    --mount=type=secret,id=actions_cache_service_v2 \
    cd src/rust && \
    SCCACHE_LAUNCHER="" && \
    if [ -s /run/secrets/actions_results_url ] && [ -s /run/secrets/actions_runtime_token ]; then \
      export SCCACHE_GHA_ENABLED=true; \
      export ACTIONS_RESULTS_URL=$(cat /run/secrets/actions_results_url); \
      export ACTIONS_RUNTIME_TOKEN=$(cat /run/secrets/actions_runtime_token); \
      export ACTIONS_CACHE_SERVICE_V2=$(cat /run/secrets/actions_cache_service_v2); \
      sccache --start-server; \
      export RUSTC_WRAPPER=sccache; \
      SCCACHE_LAUNCHER=sccache; \
    else \
      echo "No Actions cache credentials; building without sccache."; \
    fi && \
    CC=${CC:?} CXX=${CXX:?} CFLAGS="-march=haswell" CXXFLAGS="-march=haswell" ASMFLAGS="-march=haswell" RUSTFLAGS="-C linker=${CC:?}" \
    CMAKE_C_COMPILER_LAUNCHER=$SCCACHE_LAUNCHER CMAKE_CXX_COMPILER_LAUNCHER=$SCCACHE_LAUNCHER \
    cargo build --release --all-targets --all-features
RUN --mount=type=secret,id=actions_results_url \
    --mount=type=secret,id=actions_runtime_token \
    --mount=type=secret,id=actions_cache_service_v2 \
    cd src/rust && \
    SCCACHE_LAUNCHER="" && \
    if [ -s /run/secrets/actions_results_url ] && [ -s /run/secrets/actions_runtime_token ]; then \
      export SCCACHE_GHA_ENABLED=true; \
      export ACTIONS_RESULTS_URL=$(cat /run/secrets/actions_results_url); \
      export ACTIONS_RUNTIME_TOKEN=$(cat /run/secrets/actions_runtime_token); \
      export ACTIONS_CACHE_SERVICE_V2=$(cat /run/secrets/actions_cache_service_v2); \
      sccache --start-server; \
      export RUSTC_WRAPPER=sccache; \
      SCCACHE_LAUNCHER=sccache; \
    else \
      echo "No Actions cache credentials; building without sccache."; \
    fi && \
    CC=${CC:?} CXX=${CXX:?} CFLAGS="-march=haswell" CXXFLAGS="-march=haswell" ASMFLAGS="-march=haswell" RUSTFLAGS="-C linker=${CC:?}" \
    CMAKE_C_COMPILER_LAUNCHER=$SCCACHE_LAUNCHER CMAKE_CXX_COMPILER_LAUNCHER=$SCCACHE_LAUNCHER \
    cargo test  --release --all-targets --all-features

FROM base AS code_quality

COPY . src

RUN cd src && CMAKE_TOOLCHAIN_FILE=category/core/toolchains/gcc-avx2.cmake cmake -S . -B build           \
  -DMONAD_COMPILER_BENCHMARKS=On  \
  -DMONAD_COMPILER_TESTING=On     \
  -DCMAKE_BUILD_TYPE=Debug        \
  -DCMAKE_C_COMPILER=clang-19     \
  -DCMAKE_CXX_COMPILER=clang++-19 \
  -DUTILS_CLANG_TIDY_AUTO_CONST=On

RUN cd src && cmake --build build -t ConstCorrectnessChecks
RUN cd src && ./scripts/check-clang-tidy.sh

FROM base_rust AS code_quality_rust

COPY . src

RUN cd src/rust && cargo shear
RUN cd src/rust && cargo clippy --all-targets --all-features -- \
    -D clippy::suspicious \
    -D clippy::style \
    -D clippy::clone_on_copy \
    -D clippy::redundant_clone \
    -D clippy::iter_kv_map \
    -D clippy::iter_nth \
    -D clippy::unnecessary_cast \
    -D clippy::filter_next \
    -D clippy::needless_lifetimes \
    -D clippy::useless_conversion \
    -D clippy::useless_vec \
    -D clippy::needless_question_mark \
    -D clippy::bool_comparison \
    -D unused_imports \
    -D unused_parens \
    -D deprecated \
    -A clippy::type_complexity \
    -A clippy::int_plus_one \
    -A clippy::uninlined-format-args \
    -A clippy::enum-variant-names \
    -A clippy::mutable_key_type \
    -A clippy::large_enum_variant \
    -A clippy::doc-overindented-list-items
RUN cd src/rust && cargo check --all-targets --all-features
RUN cd src/rust && cargo doc --all-features --no-deps
RUN cd src/rust && cargo test --release --doc --all-features

FROM base AS base_riscv_gnu_toolchain

COPY scripts/ubuntu-build/ /opt
RUN apt-get update && \
    /opt/install-riscv-deps.sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    rm -rf /opt

RUN git clone --depth 1 --branch 2026.06.06 https://github.com/riscv-collab/riscv-gnu-toolchain /riscv-gnu-toolchain
WORKDIR /riscv-gnu-toolchain

RUN ./configure --prefix=/root/riscv \
    --with-arch=rv64ima \
    --with-abi=lp64
    
RUN make -j$(nproc)

ENV PATH="/root/riscv/bin:${PATH}"

WORKDIR /

FROM base_riscv_gnu_toolchain AS build_zk

COPY . src

RUN cd src && cmake -B build-zkvm -S zkvm/guest \
    -DCMAKE_TOOLCHAIN_FILE=/src/category/core/toolchains/riscv64-elf.cmake \
    -DRISCV_TOOLCHAIN_DIR=/root/riscv \
    -DCMAKE_BUILD_TYPE=Release
RUN cd src && cmake --build build-zkvm --target monad-zkvm --parallel

FROM base AS vm_fuzz

RUN apt-get update && apt-get install -y tmux

COPY . src

RUN cd src && CMAKE_TOOLCHAIN_FILE=category/core/toolchains/gcc-avx2.cmake cmake -S . -B build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DMONAD_COMPILER_TESTING=On \
  -DCMAKE_C_COMPILER=clang-19 \
  -DCMAKE_CXX_COMPILER=clang++-19 \
  -DCMAKE_C_COMPILER_LAUNCHER=sccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=sccache

RUN --mount=type=secret,id=actions_results_url \
    --mount=type=secret,id=actions_runtime_token \
    --mount=type=secret,id=actions_cache_service_v2 \
    cd src && \
    if [ -s /run/secrets/actions_results_url ] && [ -s /run/secrets/actions_runtime_token ]; then \
      export SCCACHE_GHA_ENABLED=true; \
      export ACTIONS_RESULTS_URL=$(cat /run/secrets/actions_results_url); \
      export ACTIONS_RUNTIME_TOKEN=$(cat /run/secrets/actions_runtime_token); \
      export ACTIONS_CACHE_SERVICE_V2=$(cat /run/secrets/actions_cache_service_v2); \
      sccache --start-server; \
    else \
      echo "No Actions cache credentials; building without sccache."; \
      cmake -B build -DCMAKE_C_COMPILER_LAUNCHER= -DCMAKE_CXX_COMPILER_LAUNCHER=; \
    fi && \
    cmake --build build -t monad-compiler-fuzzer && \
    { sccache --show-stats || true; }
RUN cd src && ./scripts/vm/ci-fuzzer.sh

FROM base AS runner
COPY --from=build /src/build/category/mpt/monad-mpt /usr/local/bin/
COPY --from=build /src/build/cmd/monad-cli /usr/local/bin/
COPY --from=build /src/build/cmd/monad /usr/local/bin/
