# Invite Code Manager

An Invite Code Manager built with **Rust**, using the **Axum** web framework, **Diesel** ORM with *
*SQLite**, and **Tokio** for asynchronous runtime. This tool manages invite codes for a PDS (
Personal Data Server).

## Table of Contents

- [Invite Code Manager](#invite-code-manager)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [Setup and Run](#setup-and-run)
    - [1. Database Migrations](#1-database-migrations)
    - [2. Run the Server](#2-run-the-server)
  - [CLI Commands](#cli-commands)
  - [API Documentation](#api-documentation)
  - [Testing](#testing)
    - [Adding New Tests](#adding-new-tests)
  - [Project Structure](#project-structure)

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (2024 edition)
- [SQLite](https://sqlite.org/index.html)
- [Diesel CLI](https://diesel.rs/guides/getting-started) (for database migrations)

## Environment Variables

The application requires several environment variables. You can set them in a `.env` file or in your
environment:

| Variable                | Description                                                                 | Required | Default |
|-------------------------|-----------------------------------------------------------------------------|----------|---------|
| `PDS_ADMIN_PASSWORD`    | Administrative password for the PDS                                         | Yes      | -       |
| `PDS_ENDPOINT`          | Endpoint URL for the PDS                                                    | Yes      | -       |
| `DATABASE_URL`          | Path to the SQLite database file                                            | Yes      | -       |
| `SESSION_SECRET`        | Session signing secret (must be at least 64 characters)                     | Yes      | -       |
| `DB_MIN_IDLE`           | Minimum number of connections in the pool                                   | No       | `1`     |
| `SERVER_PORT`           | Port the server listens on                                                  | No       | `9090`  |
| `ALLOWED_ORIGIN`        | CORS allowed origin (`*` or a specific origin like `https://app.example`) | No       | `*`     |
| `SESSION_COOKIE_SECURE` | Whether session cookies require HTTPS (`true` or `false`)                 | No       | `true`  |
| `CF_ACCESS_TEAM_DOMAIN` | Cloudflare Access team domain, e.g. `https://acme.cloudflareaccess.com`     | For `/invite-codes/issue` | - |
| `CF_ACCESS_AUD`         | AUD tag of the Access application in front of this service                  | For `/invite-codes/issue` | - |
| `CF_ACCESS_ALLOWED_SERVICE_TOKENS` | Comma-separated service token names allowed to issue codes       | No       | any     |

Example `.env`:

```bash
PDS_ADMIN_PASSWORD=your_pds_password
PDS_ENDPOINT=https://pds.example.com
DATABASE_URL=database.sqlite
SESSION_SECRET=64-character-secret-key
SESSION_COOKIE_SECURE=true
SERVER_PORT=9090
```

Generate a secure session secret on macOS/Linux:

```bash
openssl rand -base64 64
```

## Setup and Run

### 1. Database Migrations

Before running the application, ensure the database is initialized with migrations:

```bash
diesel migration run
```

### 2. Run the Server

To start the HTTP server:
```bash
cargo run
```

The server will be available at `http://localhost:9090` (or the port specified by `SERVER_PORT`).

## CLI Commands

The application provides CLI commands for administrative tasks:

- **Create a user**:
  ```bash
  cargo run -- create-user
  ```
- **List users**:
  ```bash
  cargo run -- list-users
  ```

## Machine access

`POST /invite-codes/issue` creates a **single** invite code and returns it:

```json
{ "code": "your-pds-abc12-xyz34", "useCount": 1 }
```

`POST /create-invite-codes` calls the PDS's plural endpoint, which reports only
success. A caller that needs the code for one specific person therefore has to
list every code on the PDS and diff against what it saw before — expensive, and
racy when two callers create codes at the same time. The singular endpoint
returns what it made, so one call is enough.

It authenticates through **Cloudflare Access** rather than the session cookie
the browser-facing endpoints use, because a service calling on a schedule should
not be holding an admin password.

### Setting it up

1. Put this service behind an Access application.
2. Create a **service token** (Access > Service Auth) for the caller.
3. Add a policy on the application allowing that service token.
4. Set `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` (Access > Applications >
   Overview) and restart.

Callers send the token as `CF-Access-Client-Id` and `CF-Access-Secret` headers;
Access validates it and injects a signed `Cf-Access-Jwt-Assertion`, which this
service verifies against your team's public keys — signature, audience and
expiry. The `CF-Access-Client-Id` header is deliberately *not* trusted on its
own: anything able to reach the origin directly could set it.

Optionally narrow further with `CF_ACCESS_ALLOWED_SERVICE_TOKENS`, a
comma-separated list of service token names.

> The endpoint refuses every request unless both `CF_ACCESS_TEAM_DOMAIN` and
> `CF_ACCESS_AUD` are set. A half-configured auth path fails closed rather than
> becoming an open one.

## API Documentation

The project includes built-in API documentation via Swagger UI (using `utoipa` and
`utoipa-swagger-ui`).
Once the server is running, you can access the documentation at:
`http://localhost:9090/swagger-ui`

## Testing

Tests are located in the `tests/` directory and use an in-memory SQLite database for isolation.

- **Run all tests**:
  ```bash
  cargo test
  ```
- **Run a specific test**:
  ```bash
  cargo test --test <test_name>
  ```

### Adding New Tests

When adding new integration tests, use `tests/common/mod.rs` to set up the test environment.
Typical test setup includes:

1. `common::setup_test_db()`
2. `common::init_db(&db_pool)`
3. `common::setup_app(db_pool)`

## Project Structure

```text
.
├── Cargo.toml          # Rust dependencies and metadata
├── migrations/         # Database migrations (Diesel)
├── src/                # Source code
│   ├── apis/           # Axum request handlers and route definitions
│   ├── db/             # Database connection and utilities
│   ├── cli.rs          # CLI command implementations
│   ├── config.rs       # Configuration loading from environment variables
│   ├── error.rs        # Error types and HTTP status mapping
│   ├── main.rs         # Application entry point
│   ├── schema.rs       # Auto-generated Diesel schema
│   ├── state.rs        # Shared application state
│   └── user.rs         # Admin model and session extractors
├── tests/              # Integration tests
└── README.md           # Project documentation
```
