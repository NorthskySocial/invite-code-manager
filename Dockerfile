FROM rust:latest AS builder

# Copy local code to the container image.
WORKDIR /app

COPY Cargo.toml rust-toolchain.toml ./
COPY src src

RUN cargo build --release

FROM rust:slim

RUN apt-get update
RUN apt-get install sqlite3 -y

COPY --from=builder /app/target/release/ .

ENTRYPOINT ["./InviteCodeManager"]

LABEL org.opencontainers.image.source=https://github.com/NorthskySocial/invite-code-manager
LABEL org.opencontainers.image.description="Invite Code Manager"
LABEL org.opencontainers.image.licenses=MIT