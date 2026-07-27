FROM rust:latest@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488 AS builder

# Copy local code to the container image.
WORKDIR /app

COPY Cargo.toml rust-toolchain.toml ./
COPY src src

RUN cargo build --release

FROM rust:slim@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c

RUN apt-get update
RUN apt-get install sqlite3 -y

COPY --from=builder /app/target/release/ .

ENTRYPOINT ["./invite_code_manager"]

LABEL org.opencontainers.image.source=https://github.com/NorthskySocial/invite-code-manager
LABEL org.opencontainers.image.description="Invite Code Manager"
LABEL org.opencontainers.image.licenses=MIT