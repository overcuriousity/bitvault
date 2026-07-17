FROM rust:1 AS build

WORKDIR /app

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && \
    apt-get -y install --no-install-recommends ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release && \
    mkdir -p /app/bitvault_data

# https://github.com/GoogleContainerTools/distroless
# nonroot user (uid:gid 65532:65532) is pre-defined in distroless images
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# copy time zone info from build stage
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

# copy CA certificates from build stage
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# copy built executable
COPY --from=build /app/target/release/bitvault /usr/bin/bitvault

# copy data directory skeleton with nonroot ownership
COPY --from=build --chown=65532:65532 /app/bitvault_data /app/bitvault_data

USER 65532:65532

ENV BITVAULT_DATA_DIR=/app/bitvault_data

VOLUME ["/app/bitvault_data"]

EXPOSE 8080

ENTRYPOINT ["/usr/bin/bitvault"]
