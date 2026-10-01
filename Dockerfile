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
# bitcoin-cli's counterpart: the same binary under the name helix-cli.
RUN ln -s helix /usr/local/bin/helix-cli

# The node writes validator-key.json and helix-data.redb into its working
# directory — mount a volume here to persist validator identity + chain state
# across container restarts/upgrades.
WORKDIR /data

# 8547: the wallet RPC for exchanges, served by the node itself — `server=1` in the wallet's
# helix.conf (or HELIX_WALLET_RPC). Inside a container, bind it to 0.0.0.0 and name the Docker
# network that may connect (rpcallowip=172.16.0.0/12): connections through Docker do not come from
# loopback, and nobody else is let in. Keep the port off the internet.
EXPOSE 8545 8546 8547

ENTRYPOINT ["/usr/local/bin/helix", "start"]
