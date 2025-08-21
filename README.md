# Security Alert Backend — Local PostgreSQL for Frontend

This repository primarily uses ClickHouse for backend analytics. For frontend development you requested a local PostgreSQL instance — the files below provide a simple Docker Compose setup and init script.

Files added:
- `docker-compose.postgres.yml` — PostgreSQL + optional pgAdmin service for local development
- `scripts/db/init_postgres.sql` — initial SQL run at first container start (creates sample DB/user)

Quick start

1. Copy or update credentials (recommended: do NOT use these in production):

   - DB name: `socconnect_frontend`
   - DB user: `socfront`
   - DB password: `changeme`

2. Start PostgreSQL (from repo root):

```bash
docker compose -f docker-compose.postgres.yml up -d
```

3. Verify connectivity (requires psql CLI):

```bash
psql "postgresql://socfront:changeme@localhost:5432/socconnect_frontend" -c "\dt"
```

4. Environment variable example (create `.env.postgres` or add to your app env):

```
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=socconnect_frontend
POSTGRES_USER=socfront
POSTGRES_PASSWORD=changeme
POSTGRES_URL=postgresql://socfront:changeme@localhost:5432/socconnect_frontend
```

Creating application tables

- Use `psql` or your preferred migration tool to create tables. Example:

```bash
psql "$POSTGRES_URL" -f scripts/db/init_postgres.sql
```

Notes

- The init SQL is idempotent and safe to run multiple times.
- Change passwords before sharing or deploying.
- If you prefer a different DB user/DB name, update `docker-compose.postgres.yml` and `.env` accordingly.

If you want, I can:
- Add a simple Node.js migration script using `node-postgres` to apply `init_postgres.sql` automatically.
- Create a `.env.example` and update app config to read `POSTGRES_URL`.

# SocConnectDummyTrial
