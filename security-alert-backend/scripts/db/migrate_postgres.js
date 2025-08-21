#!/usr/bin/env node
// Simple migration script to apply SQL files to PostgreSQL using node-postgres
// Usage: node scripts/db/migrate_postgres.js --file=./security-alert-backend/scripts/db/init_postgres.sql

const fs = require('fs');
const { Client } = require('pg');
const argv = require('minimist')(process.argv.slice(2));

const file = argv.file || './security-alert-backend/scripts/db/init_postgres.sql';
const connection = process.env.POSTGRES_URL || 'postgresql://socfront:changeme@localhost:5432/socconnect_frontend';

(async function main() {
  try {
    const sql = fs.readFileSync(file, 'utf8');
    const client = new Client({ connectionString: connection });
    await client.connect();
    console.log('Connected to Postgres');
    await client.query('BEGIN');
    // split on semicolon at EOL is naive; keep simple for init script
    const statements = sql.split(/;\s*\n/).map(s=>s.trim()).filter(Boolean);
    for (const stmt of statements) {
      console.log('Executing:', stmt.substring(0,80).replace(/\n/g,' '),'...');
      await client.query(stmt);
    }
    await client.query('COMMIT');
    console.log('Migration complete');
    await client.end();
  } catch (err) {
    console.error('Migration failed', err.message);
    process.exit(1);
  }
})();
