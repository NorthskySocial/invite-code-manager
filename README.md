# <h1> Invite Code Manager </h1>
[![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/mit)

## Overview

Backend Application that acts as a middleman to manage invite codes. Purpose is to avoid having to share the admin password for the PDS with many users

## Setup

To set up the application, you will need to have [Rust](https://www.rust-lang.org/tools/install) and [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed on your system, then follow these steps:

### Environment variables

Clone the repository and fill-in the environment variables in a `.env` file. You can use the `.env.sample` as a template.

```bash
cp .env.sample .env
nano .env # or use your favorite editor
```

### Database

Run the migrations to set up the SQLite database. You will need to have [Diesel CLI](https://diesel.rs/guides/getting-started#installing-diesel-cli) installed.

If you don't have it installed, you can do so with the following command (or read more in the link above):

```bash
cargo install diesel_cli --no-default-features --features sqlite
```

To run the migrations, use the following command:

```bash
diesel migration run
```

### Creating an Admin User

After setting up the database, you can create an admin user interactively using the CLI:

```bash
cargo run -- create-user
```

This will prompt you to enter a username and password for a new admin user.

Note that this user is NOT the same as a Bluesky user in your PDS, but a separate entity that is used to manage the invite codes.

## Usage

Once the setup process is complete, use `cargo` to run the application:

```bash
cargo run
```

The application will start a web server on the specified port. You can use the [invite code client](https://github.com/NorthskySocial/invite-code-client) to interact with the server.

## What Needs Work

- Proper error handling
- Reorganize code to clean up
- Much more
