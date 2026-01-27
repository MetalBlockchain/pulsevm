FROM ubuntu:24.04
RUN apt-get update -y

# Install rust
RUN apt-get install curl -y
RUN curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh -s -- -y

# Install dependencies
RUN apt-get install -y \
    gcc-13 \
    g++-13 \
    cmake \
    libgmp-dev \
    zlib1g-dev \
    unzip \
    pkg-config \
    libboost-all-dev \
    libcurl4-openssl-dev \
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

ENV CXX=/usr/bin/g++-13
ENV CC=/usr/bin/gcc-13
ENV BOOST_LIB=/usr/lib/x86_64-linux-gnu
ENV ZLIB_ROOT=/usr/lib/x86_64-linux-gnu

RUN cargo build --release