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
  {
    name: '005_zt_checks',
    sql: `
      -- 제로트러스트 판정 기록. forward-auth 는 요청마다 불리므로 캐시 TTL(기본 60초) 안에서는 1건만 남는다.
      CREATE TABLE zt_checks (
        id BIGSERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        host TEXT NOT NULL,
        ip TEXT NOT NULL,
        verdict TEXT NOT NULL,
        device_id TEXT,
        device_hostname TEXT,
        mode TEXT NOT NULL,
        allowed BOOLEAN NOT NULL,
        error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX zt_checks_created ON zt_checks (created_at DESC);
      CREATE INDEX zt_checks_email ON zt_checks (email, created_at DESC);
    `,
  },
  {
    name: '006_sliding_sessions',
    sql: `
      -- sliding 세션: expires_at 은 유휴 만료(활동마다 연장), absolute_expires_at 은 로그인 기준 상한.
      ALTER TABLE sessions
        ADD COLUMN last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        ADD COLUMN absolute_expires_at TIMESTAMPTZ;
      -- 기존(고정 12h) 세션은 새 기본 정책(유휴 24h, 상한 7일)으로 옮긴다.
      -- 만료된 세션은 건드리지 않는다(상한도 과거로 두어 그대로 정리되게).
      UPDATE sessions
      SET absolute_expires_at = created_at + interval '168 hours',
          expires_at = LEAST(now() + interval '24 hours', created_at + interval '168 hours')
      WHERE expires_at > now();
      UPDATE sessions SET absolute_expires_at = expires_at WHERE absolute_expires_at IS NULL;
      ALTER TABLE sessions ALTER COLUMN absolute_expires_at SET NOT NULL;
    `,
  },
  {
    name: '007_revoked_before',
    sql: `
      -- 회수 전파(GET /internal/account): 이 시각 이전에 발급된 앱 세션·토큰은 무효.
      -- NULL 허용·기본값 없음이라 기존 행을 다시 쓰지 않는다(메타데이터만 바뀜).
      ALTER TABLE users ADD COLUMN revoked_before TIMESTAMPTZ;
    `,
  },
  {
    name: '008_app_access',
    sql: `
      -- 앱별 접근 정책. app_key 는 forward-auth 호스트(소문자) 또는 'oidc:<client_id>'.
      -- 행이 없거나 mode='all' 이면 활성 사용자 전원 허용(배포만으로는 동작이 바뀌지 않는다).
      CREATE TABLE app_policies (
        app_key TEXT PRIMARY KEY,
        mode TEXT NOT NULL DEFAULT 'all' CHECK (mode IN ('all', 'restricted')),
        note TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE app_access (
        app_key TEXT NOT NULL REFERENCES app_policies(app_key) ON DELETE CASCADE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (app_key, user_id)
      );
    `,
  },
  {
    name: '009_admin_events',
    sql: `
      -- 관리자 작업 감사 로그. 시크릿 값은 절대 detail 에 넣지 않는다.
      CREATE TABLE admin_events (
        id BIGSERIAL PRIMARY KEY,
        actor_id INT REFERENCES users(id) ON DELETE SET NULL,
        actor_email TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        detail JSONB NOT NULL DEFAULT '{}',
        ip TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX admin_events_created ON admin_events (created_at DESC);
    `,
  },
  {
    name: '010_zt_reason_restricted',
    sql: `
      -- reason: ward 가 verdict 에 덧붙인 기계용 사유(예: agent_offline). restricted: 소프트 호스트라 통과시켰지만 원래는 거부될 판정.
      -- 둘 다 NULL 허용이고 기본값은 상수라 기존 행을 다시 쓰지 않는다(PG 11+ 에서 메타데이터만 바뀜). 옛 행은 reason NULL · restricted false 로 읽힌다.
      ALTER TABLE zt_checks
        ADD COLUMN reason TEXT,
        ADD COLUMN restricted BOOLEAN DEFAULT false;
    `,
  },
];

export async function migrate(): Promise<void> {
  // 한 연결에서 advisory lock 을 잡고 전부 돌린다. 여러 프로세스(동시에 뜨는 테스트 파일들, 겹쳐 뜨는 컨테이너)가
  // 같은 마이그레이션을 동시에 적용하려다 "already exists" 로 죽지 않게 — 늦게 온 쪽은 기다렸다가 적용 목록을 다시 읽는다.
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock(727001)');
    await client.query(`
      CREATE TABLE IF NOT EXISTS _migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    const { rows } = await client.query<{ name: string }>('SELECT name FROM _migrations');
    const applied = new Set(rows.map((r) => r.name));

    for (const m of migrations) {
      if (applied.has(m.name)) continue;
      try {
        await client.query('BEGIN');
        await client.query(m.sql);
        await client.query('INSERT INTO _migrations (name) VALUES ($1)', [m.name]);
        await client.query('COMMIT');
        console.log(`migrated: ${m.name}`);
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock(727001)').catch(() => {});
    client.release();
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
