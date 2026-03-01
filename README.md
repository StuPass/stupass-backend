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
| Authentication    | JWT (jsonwebtoken)                            |
| Password Hashing  | Argon2                                        |
| Validation        | validator                                     |

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

| Method | Endpoint                   | Description                       |
| ------ | -------------------------- | --------------------------------- |
| POST   | `/auth/register`           | Register new user                 |
| POST   | `/auth/login`              | User login                        |
| POST   | `/auth/logout`             | User logout                       |
| POST   | `/auth/refresh`            | Refresh access token              |
| POST   | `/auth/forgot-password`    | Request password reset            |
| POST   | `/auth/reset-password`     | Reset password with token         |
| GET    | `/auth/verify-email`       | Verify email address              |
| GET    | `/auth/check-status`       | Check verification status         |
| POST   | `/auth/resend-verification`| Resend verification email         |

## Project Structure

```
stupass-backend/
├── src/
│   ├── main.rs              # Application entry point, router configuration
│   ├── lib.rs               # Library exports
│   ├── config.rs            # Configuration management
│   ├── state.rs             # Application state
│   ├── errors.rs            # Error types
│   ├── rate_limit.rs        # Rate limiting logic
│   ├── entities/            # SeaORM entity definitions
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── credential.rs
│   │   ├── session.rs
│   │   ├── auth_provider.rs
│   │   └── password_reset_token.rs
│   ├── handlers/            # Request handlers
│   │   ├── mod.rs
│   │   ├── auth.rs          # Authentication endpoints
│   │   └── general.rs       # Health check & general endpoints
│   ├── services/            # Business logic layer
│   │   ├── mod.rs
│   │   ├── email.rs         # Email service (Resend API)
│   │   └── auth/            # Auth services
│   │       ├── mod.rs
│   │       ├── login.rs
│   │       ├── register.rs
│   │       ├── password.rs
│   │       └── session.rs
│   ├── models/              # DTOs and request/response types
│   │   ├── mod.rs
│   │   └── auth.rs
│   ├── middleware/          # Axum middleware
│   │   ├── mod.rs
│   │   └── auth_middleware.rs
│   ├── extractors/          # Custom request extractors
│   │   ├── mod.rs
│   │   └── validation.rs    # ValidJson extractor
│   └── utils/               # Utility functions
│       ├── mod.rs
│       └── jwt_token.rs
├── tests/                   # Integration tests
│   ├── common/              # Test utilities
│   │   ├── mod.rs
│   │   ├── db.rs
│   │   ├── fixtures.rs
│   │   ├── mock_email.rs
│   │   └── request.rs
│   ├── auth_register.rs
│   ├── auth_login.rs
│   ├── auth_logout.rs
│   ├── auth_refresh.rs
│   ├── auth_forgot_password.rs
│   ├── auth_reset_password.rs
│   ├── auth_verify_email.rs
│   └── health.rs
├── migration/               # Database migrations (SeaORM)
├── seeder/                  # Test data seeder CLI
├── Cargo.toml
└── CLAUDE.md                # Project documentation for AI assistants
```

## Testing

Run all tests:

```bash
cargo test
```

Run specific test file:

```bash
cargo test --test auth_login
```

### Test Coverage

- Registration flow with validation
- Login with credential verification
- Session management (logout, refresh)
- Password reset flow
- Email verification
- Health check endpoint

## Database Migrations

Run migrations from the `migration` directory:

```bash
cd migration
cargo run
```

## Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL=sqlite:data.db?mode=rwc
JWT_SECRET=your-secret-key
RESEND_API_KEY=your-resend-api-key
FE_URL=http://localhost:5173
SERVER_URL=http://localhost:3000
```

## License

This project is an extracurricular initiative developed in January 2025.

## References

- [StuPass Initial Design Document](https://github.com/StuPass/StuPass-Docs/blob/main/StuPass_Initial_Design.pdf)
- [CONTRIBUTING.md](CONTRIBUTING.md)
