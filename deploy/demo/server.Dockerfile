FROM rust:1.97.1-bookworm AS build

WORKDIR /source
COPY . .
RUN cargo build --locked --release --package faultlane-server --package faultlane-cli

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl docker.io \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /source/target/release/faultlane-server /usr/local/bin/faultlane-server
COPY --from=build /source/target/release/faultlane /usr/local/bin/faultlane
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/faultlane-server"]
