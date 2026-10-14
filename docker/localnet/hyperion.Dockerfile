# syntax=docker/dockerfile:1
FROM rust:1.96.1-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY --from=hyperion /Cargo.toml /Cargo.lock ./
COPY --from=hyperion /crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p hyperion \
    && install -Dm755 target/release/hyperion /out/hyperion

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/hyperion /usr/local/bin/hyperion
ENTRYPOINT ["hyperion"]
