# syntax=docker/dockerfile:1

# --- Builder ---------------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --bin helix --bin helix-mesh --bin helix-walletd

# --- Runtime -----------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/helix /usr/local/bin/helix
# For exchanges: the Mesh (Rosetta) Data API and the Bitcoin-Core-style wallet RPC, each run as
# its own container from this image with `--entrypoint helix-mesh` / `--entrypoint helix-walletd`.
COPY --from=builder /build/target/release/helix-mesh /usr/local/bin/helix-mesh
COPY --from=builder /build/target/release/helix-walletd /usr/local/bin/helix-walletd

# The node writes validator-key.json and helix-data.redb into its working
# directory — mount a volume here to persist validator identity + chain state
# across container restarts/upgrades.
WORKDIR /data

EXPOSE 8545 8546

ENTRYPOINT ["/usr/local/bin/helix", "start"]
