FROM rust:1.97.1-bookworm AS build

WORKDIR /source
COPY . .
RUN cargo build --locked --release --package faultlane-cli

FROM debian:bookworm-slim

COPY --from=build /source/target/release/faultlane /usr/local/bin/faultlane
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/faultlane"]
