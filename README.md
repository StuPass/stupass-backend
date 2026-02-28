# StuPass Backend

Backend service for **StuPass**. Built with Rust, Axum, and SeaORM.

## Overview

StuPass enables verified students to buy and sell items within their institutional community. Key features include:

- Student verification via institutional email
- Product listings with multi-image support
- Real-time messaging between buyers and sellers
- Reputation system
- Transaction history organized as visual collections

## Tech Stack

| Component         | Technology                                    |
| ----------------- | --------------------------------------------- |
| Web Framework     | Axum 0.8                                      |
| ORM               | SeaORM 1.1                                    |
| Database          | SQLite (development), PostgreSQL (production) |
| Async Runtime     | Tokio                                         |
| API Documentation | utoipa / Swagger UI                           |
| Serialization     | serde / serde_json                            |
| Logging           | tracing / tracing-subscriber                  |

## Prerequisites

- **Rust** 1.85+ (Edition 2024)
- **cargo-watch** (optional, for continuous development)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/StuPass/stupass-backend.git
cd stupass-backend
```

### 2. Install cargo-watch (for continuous mode)

```bash
cargo install cargo-watch
```

`cargo-watch` monitors file changes and automatically rebuilds/restarts the application during development.

## Running the Server

### One-shot mode

Build and run once:

```bash
cargo run --bin stupass-backend
```

### Continuous mode (development)

Auto-rebuild on file changes:

```bash
cargo watch -x 'run --bin stupass-backend'
```

The server starts at `http://127.0.0.1:3000`.

## API Documentation

Swagger UI is available at the root endpoint:

```
http://127.0.0.1:3000/
```

## API Endpoints

### General

| Method | Endpoint  | Description  |
| ------ | --------- | ------------ |
| GET    | `/health` | Health check |

### Authentication

| Method | Endpoint                | Description               |
| ------ | ----------------------- | ------------------------- |
| POST   | `/auth/register`        | Register new user         |
| POST   | `/auth/login`           | User login                |
| POST   | `/auth/logout`          | User logout               |
| POST   | `/auth/refresh`         | Refresh access token      |
| POST   | `/auth/forgot-password` | Request password reset    |
| POST   | `/auth/reset-password`  | Reset password with token |
| GET    | `/auth/verify-email`    | Verify email address      |

## Project Structure

```
stupass-backend/
├── src/
│   ├── main.rs           # Application entry point, router configuration
│   ├── lib.rs            # Library exports
│   ├── entities/         # SeaORM entity definitions
│   └── handlers/         # Request handlers
│       ├── mod.rs
│       ├── auth.rs       # Authentication endpoints
│       └── general.rs    # Health check & other general purpose endpoints
├── migration/            # Database migrations (SeaORM)
├── Cargo.toml
```

## Database Migrations

Run migrations from the `migration` directory:

```bash
cd migration
cargo run
```

## Environment Variables

Create a `.env` file in the project root (see `.env.example` if available).

## License

This project is an extracurricular initiative developed in January 2025.

## References

- [StuPass Initial Design Document](https://github.com/StuPass/StuPass-Docs/blob/main/StuPass_Initial_Design.pdf)
- [CONTRIBUTING.md](CONTRIBUTING.md)
