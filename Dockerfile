FROM rust:1.98-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS builder

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

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/invite_code_manager .

ENTRYPOINT ["./invite_code_manager"]

LABEL org.opencontainers.image.source=https://github.com/NorthskySocial/invite-code-manager
LABEL org.opencontainers.image.description="Invite Code Manager"
LABEL org.opencontainers.image.licenses=MIT