# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.97.1

FROM rust:${RUST_VERSION}-bookworm AS toolchain
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
WORKDIR /workspace

FROM toolchain AS dev
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install cargo-watch --version 8.5.3 --locked
COPY . .
ENV CARGO_TARGET_DIR=/workspace/target
EXPOSE 8081
CMD ["cargo", "watch", "--why", "-x", "run --locked -p zeus-api"]

FROM dev AS debug
RUN apt-get update \
    && apt-get install -y --no-install-recommends gdbserver \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 2345
CMD ["sh", "-lc", "cargo build --locked -p zeus-api && exec gdbserver 0.0.0.0:2345 target/debug/zeus-api"]

FROM toolchain AS builder
COPY Cargo.toml Cargo.lock ./
COPY apps/zeus-api apps/zeus-api
COPY crates crates
RUN --mount=type=cache,id=zeus-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=zeus-cargo-target,target=/workspace/target \
    cargo build --locked --release -p zeus-api \
    && install -D -m 0755 target/release/zeus-api /out/zeus-api

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system zeus \
    && useradd --system --gid zeus --home-dir /nonexistent --shell /usr/sbin/nologin zeus \
    && install -d -o zeus -g zeus -m 0750 /var/lib/zeus
COPY --from=builder /out/zeus-api /usr/local/bin/zeus
USER zeus
ENV ZEUS_LISTEN_ADDR=0.0.0.0:8081
ENV ZEUS_DATABASE_PATH=/var/lib/zeus/zeus.db
ENV ZEUS_DEMO_PROFILE=production-guarded
ENV ZEUS_LOCAL_MARKER_ROOT=/var/lib/zeus/local-markers
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/zeus"]
