import { pool } from './pool.js';

const migrations: { name: string; sql: string }[] = [
  {
    name: '001_initial',
    sql: `
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        google_sub TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hd TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        picture TEXT,
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_login_at TIMESTAMPTZ
      );

      CREATE TABLE sessions (
        id SERIAL PRIMARY KEY,
        token_hash TEXT UNIQUE NOT NULL,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL,
        ip TEXT,
        user_agent TEXT
      );
      CREATE INDEX sessions_expires ON sessions (expires_at);

      CREATE TABLE login_events (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        email TEXT NOT NULL,
        event TEXT NOT NULL CHECK (event IN ('login', 'logout', 'denied')),
        detail TEXT,
        ip TEXT,
        user_agent TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX login_events_created ON login_events (created_at DESC);
    `,
  },
  {
    name: '002_admin',
    sql: `
      ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false;
    `,
  },
  {
    name: '003_oidc',
    sql: `
      CREATE TABLE oidc_clients (
        id SERIAL PRIMARY KEY,
        client_id TEXT UNIQUE NOT NULL,
        client_secret TEXT NOT NULL,
        name TEXT NOT NULL,
        redirect_uris TEXT[] NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE oidc_jwks (
        id SERIAL PRIMARY KEY,
        jwk JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `,
  },
  {
    name: '004_client_grants',
    sql: `
      ALTER TABLE oidc_clients
        ADD COLUMN grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code'],
        ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post';
    `,
  },
];

export async function migrate(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS _migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  const { rows } = await pool.query<{ name: string }>('SELECT name FROM _migrations');
  const applied = new Set(rows.map((r) => r.name));

  for (const m of migrations) {
    if (applied.has(m.name)) continue;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(m.sql);
      await client.query('INSERT INTO _migrations (name) VALUES ($1)', [m.name]);
      await client.query('COMMIT');
      console.log(`migrated: ${m.name}`);
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
