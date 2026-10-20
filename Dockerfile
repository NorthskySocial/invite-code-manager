FROM rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a AS builder

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

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/invite_code_manager .

ENTRYPOINT ["./invite_code_manager"]

LABEL org.opencontainers.image.source=https://github.com/NorthskySocial/invite-code-manager
LABEL org.opencontainers.image.description="Invite Code Manager"
LABEL org.opencontainers.image.licenses=MIT