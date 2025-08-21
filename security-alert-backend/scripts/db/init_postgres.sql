-- init_postgres.sql - Docker-entrypoint friendly idempotent setup for frontend DB
-- This script is executed by the postgres container entrypoint from /docker-entrypoint-initdb.d
-- The container will run this script against the database defined by POSTGRES_DB.

-- create role if running as superuser (safe to execute)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'socfront') THEN
    CREATE ROLE socfront LOGIN PASSWORD 'changeme';
  END IF;
END$$;

-- ensure extension for gen_random_uuid() exists before using it
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The entrypoint runs this file within the POSTGRES_DB context (as defined in docker-compose).
-- Create example table for frontend (users)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL UNIQUE,
  display_name TEXT,
  email TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- sample data
INSERT INTO users (username, display_name, email) VALUES
('alice', 'Alice Admin', 'alice@example.local')
ON CONFLICT DO NOTHING;
