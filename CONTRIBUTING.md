# Contribution Guide

## Migration Workflow

### Creating New Migrations

1. Create a new migration file in `migration/src/` with format:
   ```
   mYYYYMMDD_INDEX_PURPOSE.rs
   ```
   Example: `m20260215_000001_init_auth_schema.rs`

2. Register the migration in `migration/src/lib.rs`

3. Run migration to apply:
   ```bash
   cargo run -p migration -- up
   ```

### Editing Existing Migrations

**Rule: Only edit the LATEST migration file.**

If you need to edit an earlier migration, you must:
1. Notify all team members beforehand
2. Get approval before proceeding

#### Procedure to Edit Latest Migration

1. **Ensure database is up-to-date:**
   ```bash
   cargo run -p migration -- up
   ```
   This applies all pending migrations automatically.

2. **Revert the latest migration (single step down):**
   ```bash
   cargo run -p migration -- down
   ```

3. **Edit the migration file** in `migration/src/`

4. **Re-apply the migration:**
   ```bash
   cargo run -p migration -- up
   ```

### Useful Migration Commands

```bash
# Apply all pending migrations
cargo run -p migration -- up

# Revert last migration (single step)
cargo run -p migration -- down

# Revert all migrations
cargo run -p migration -- reset

# View migration status
cargo run -p migration -- status

# Fresh database (reset + up)
cargo run -p migration -- fresh
```

## Entity Generation

After modifying migrations and applying them to the database, regenerate entities:

**Bash (Linux/macOS/Git Bash):**

```bash
sea-orm-cli generate entity \
  -o ./src/entities \
  -d sqlite://data.db?mode=rwc
```

**PowerShell:**

```powershell
sea-orm-cli generate entity `
  -o ./src/entities `
  -d sqlite://data.db?mode=rwc
```

**Single Line:**

```bash
sea-orm-cli generate entity -o ./src/entities -d sqlite://data.db?mode=rwc
```

### Important Notes on Entity Generation

- Entities are **read-only** - do not manually edit generated files
- Use `*_null` helpers in migrations for nullable fields (e.g., `string_null()`, `timestamp_null()`)
- The `.null()` chain method does NOT work correctly with shortcut helpers - always use `*_null` variants

### Nullable Field Reference

| Type      | Not Null         | Nullable              |
| --------- | ---------------- | --------------------- |
| String    | `string(col)`    | `string_null(col)`    |
| Integer   | `integer(col)`   | `integer_null(col)`   |
| UUID      | `uuid(col)`      | `uuid_null(col)`      |
| Timestamp | `timestamp(col)` | `timestamp_null(col)` |
| Date      | `date(col)`      | `date_null(col)`      |
| Boolean   | `boolean(col)`   | `boolean_null(col)`   |

## Domain Models

Domain models are located in `src/models/` and provide:

- Serde serialization support
- `From<entity::Model>` for database → domain conversion
- `TryFrom<Domain>` for domain → ActiveModel conversion

After regenerating entities, verify domain models still compile:

```bash
cargo check
```
