FROM ubuntu:24.04
RUN apt-get update -y

# Install rust
RUN apt-get install curl -y
RUN curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh -s -- -y

# Wasmer's LLVM backend is pinned to LLVM 22.
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-22 main" > /etc/apt/sources.list.d/llvm.list && \
    apt-get update -y

# Install dependencies
RUN apt-get install -y \
    gcc-13 \
    cmake \
    zlib1g-dev \
    unzip \
    pkg-config \
    llvm-22-dev \
    libpolly-22-dev \
    file 

# Add Rust to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Install protoc
RUN curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v27.1/protoc-27.1-linux-x86_64.zip && \
    unzip protoc-27.1-linux-x86_64.zip -d /usr/local && \
    rm protoc-27.1-linux-x86_64.zip

# Copy files
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY src src
COPY crates crates

ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22

RUN cargo build --release
