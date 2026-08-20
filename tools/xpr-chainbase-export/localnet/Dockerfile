FROM ubuntu:22.04

ARG LEAP_VERSION=5.0.3

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl \
    && curl --fail --location --retry 3 \
        --output /tmp/leap.deb \
        "https://github.com/AntelopeIO/leap/releases/download/v${LEAP_VERSION}/leap_${LEAP_VERSION}_amd64.deb" \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/leap.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/leap.deb
