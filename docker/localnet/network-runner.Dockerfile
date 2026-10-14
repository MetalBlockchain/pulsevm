# syntax=docker/dockerfile:1
# Keep the VM on Ubuntu 22.04, matching the release glibc baseline.
FROM ubuntu:22.04 AS pulsevm-build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg build-essential cmake pkg-config \
    libssl-dev libzstd-dev zlib1g-dev unzip git \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
       | gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] https://apt.llvm.org/jammy/ llvm-toolchain-jammy-22 main' \
       > /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y --no-install-recommends llvm-22-dev libpolly-22-dev \
    && rm -rf /var/lib/apt/lists/*
ARG RUST_VERSION=1.96.1
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
ENV PATH=/root/.cargo/bin:$PATH LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
ARG TARGETARCH
RUN curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v27.1/protoc-27.1-linux-$(case "$TARGETARCH" in amd64) echo x86_64;; arm64) echo aarch_64;; *) exit 1;; esac).zip" \
    -o /tmp/protoc.zip && unzip -q /tmp/protoc.zip -d /usr/local && rm /tmp/protoc.zip
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p pulsevm \
    && install -Dm755 target/release/pulsevm /out/pulsevm

FROM golang:1.25-bookworm AS runner-build
ARG NETWORK_RUNNER_REF=869d8a0cd62dac3a0fd1c503a36bdd6dfabda025
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out go install "github.com/MetalBlockchain/metal-network-runner@${NETWORK_RUNNER_REF}"

FROM ubuntu:22.04 AS metalgo-download
ARG METALGO_VERSION=v1.14.2-tahoe
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL "https://github.com/MetalBlockchain/metalgo/releases/download/${METALGO_VERSION}/metalgo-linux-${TARGETARCH}-${METALGO_VERSION}.tar.gz" \
       -o /tmp/metalgo.tar.gz \
    && mkdir /unpack /out && tar -xzf /tmp/metalgo.tar.gz -C /unpack \
    && find /unpack -type f -name metalgo -exec install -m755 '{}' /out/metalgo \; \
    && test -x /out/metalgo

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl jq gettext-base libffi8 libstdc++6 libzstd1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=pulsevm-build /out/pulsevm /opt/plugins/rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs
COPY --from=runner-build /out/metal-network-runner /usr/local/bin/metal-network-runner
COPY --from=metalgo-download /out/metalgo /usr/local/bin/metalgo
COPY chain_config.json /opt/localnet/default-chain-config.json
COPY docker/localnet/bootstrap.sh docker/localnet/healthcheck.sh docker/localnet/hyperion.toml /opt/localnet/
RUN chmod +x /opt/localnet/bootstrap.sh /opt/localnet/healthcheck.sh
ENTRYPOINT ["/opt/localnet/bootstrap.sh"]
