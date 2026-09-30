# syntax=docker/dockerfile:1

# --- Builder ---------------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --bin helix

# --- Runtime -----------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/helix /usr/local/bin/helix

# The node writes validator-key.json and helix-data.redb into its working
# directory — mount a volume here to persist validator identity + chain state
# across container restarts/upgrades.
WORKDIR /data

# 8547: the wallet RPC for exchanges, served by the node itself with HELIX_WALLET_RPC set
# (bind it to 0.0.0.0:8547 inside a container, and keep the port off the internet).
EXPOSE 8545 8546 8547

ENTRYPOINT ["/usr/local/bin/helix", "start"]
