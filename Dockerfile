FROM rust:1.92-trixie@sha256:f58923369ba295ae1f60bc49d03f2c955a5c93a0b7d49acfb2b2a65bebaf350d AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libsqlite3-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy local code to the container image.
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp target/release/invite_code_manager /app/invite_code_manager

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/invite_code_manager .

ENTRYPOINT ["./invite_code_manager"]

LABEL org.opencontainers.image.source=https://github.com/NorthskySocial/invite-code-manager
LABEL org.opencontainers.image.description="Invite Code Manager"
LABEL org.opencontainers.image.licenses=MIT