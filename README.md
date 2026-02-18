# Invite Code Manager

An Invite Code Manager built with **Rust**, using the **Axum** web framework, **Diesel** ORM with *
*SQLite**, and **Tokio** for asynchronous runtime. This tool manages invite codes for a PDS (
Personal Data Server).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Setup and Run](#setup-and-run)
- [CLI Commands](#cli-commands)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (2024 edition)
- [SQLite](https://sqlite.org/index.html)
- [Diesel CLI](https://diesel.rs/guides/getting-started) (for database migrations)

## Environment Variables

The application requires several environment variables. You can set them in a `.env` file or in your
environment:

| Variable             | Description                                    | Required | Default |
|----------------------|------------------------------------------------|----------|---------|
| `PDS_ADMIN_PASSWORD` | Administrative password for the PDS            | Yes      | -       |
| `PDS_ENDPOINT`       | The endpoint URL for the PDS                   | Yes      | -       |
| `DATABASE_URL`       | Path to the SQLite database file               | Yes      | -       |
| `DB_MIN_IDLE`        | Minimum number of idle connections in the pool | No       | `1`     |
| `SERVER_PORT`        | Port the server listens on                     | No       | `9090`  |
| `ALLOWED_ORIGIN`     | CORS allowed origin                            | No       | `*`     |

Example `.env`:

```bash
PDS_ADMIN_PASSWORD=your_pds_password
PDS_ENDPOINT=https://pds.example.com
DATABASE_URL=sqlite://invitemanager.sqlite
SERVER_PORT=9090
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
│   ├── auth/           # Authentication logic (TOTP, Sessions)
│   ├── db/             # Database connection and utilities
│   ├── models/         # Data models and schemas
│   ├── cli.rs          # CLI command implementations
│   ├── config.rs       # Configuration loading from environment variables
│   ├── main.rs         # Application entry point
│   ├── schema.rs       # Auto-generated Diesel schema
│   └── state.rs        # Shared application state
├── tests/              # Integration tests
└── README.md           # Project documentation
```