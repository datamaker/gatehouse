import { randomBytes } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { query } from '../db/pool.js';
import { SESSION_COOKIE, getSessionUser, type SessionUser } from '../auth/session.js';
import { config } from '../config.js';
import { logAdminEvent } from '../auth/audit.js';
import { revokeAccount } from '../oidc/adapter.js';
import { invalidateAppAccess, isValidAppKey, normalizeAppKey, oidcAppKey } from '../auth/appAccess.js';
import { zeroTrust } from '../zt/index.js';

const ALLOWED_GRANT_TYPES = [
  'authorization_code',
  'urn:ietf:params:oauth:grant-type:device_code',
];
const ALLOWED_AUTH_METHODS = ['client_secret_post', 'client_secret_basic', 'none'];

interface ClientBody {
  client_id?: string;
  name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  token_endpoint_auth_method?: string;
}

/** Validates the optional grant/auth-method fields; returns an error message or null. */
function validateClientOptions(body: ClientBody): string | null {
  if (body.grant_types !== undefined) {
    if (!Array.isArray(body.grant_types) || body.grant_types.length === 0) {
      return 'grant_types must be a non-empty array';
    }
    if (body.grant_types.some((g) => !ALLOWED_GRANT_TYPES.includes(g))) {
      return `grant_types must be a subset of: ${ALLOWED_GRANT_TYPES.join(', ')}`;
    }
  }
  if (
    body.token_endpoint_auth_method !== undefined &&
    !ALLOWED_AUTH_METHODS.includes(body.token_endpoint_auth_method)
  ) {
    return `token_endpoint_auth_method must be one of: ${ALLOWED_AUTH_METHODS.join(', ')}`;
  }
  if (
    body.redirect_uris?.some((u) => !/^https:\/\//.test(u) && !/^http:\/\/localhost/.test(u))
  ) {
    return 'redirect_uris must be https (or localhost)';
  }
  return null;
}

async function requireAdmin(
  req: FastifyRequest,
  reply: FastifyReply,
): Promise<SessionUser | null> {
  const token = req.cookies[SESSION_COOKIE];
  const user = token ? await getSessionUser(token) : null;
  if (!user) {
    reply.code(401).send({ error: 'not signed in' });
    return null;
  }
  if (!user.is_admin) {
    reply.code(403).send({ error: 'admin only' });
    return null;
  }
  return user;
}

export function registerAdminRoutes(app: FastifyInstance): void {
  app.get('/api/admin/users', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const { rows } = await query(
      `SELECT u.id, u.email, u.name, u.hd, u.picture, u.is_active, u.is_admin,
              u.created_at, u.last_login_at,
              count(s.id) FILTER (WHERE s.expires_at > now())::int AS active_sessions
       FROM users u
       LEFT JOIN sessions s ON s.user_id = u.id
       GROUP BY u.id
       ORDER BY u.last_login_at DESC NULLS LAST`,
    );
    return rows;
  });

  app.patch('/api/admin/users/:id', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const id = parseInt((req.params as { id: string }).id, 10);
    const body = req.body as { is_active?: boolean; is_admin?: boolean };

    // Lockout guard: you cannot deactivate or demote yourself.
    if (id === admin.id && (body.is_active === false || body.is_admin === false)) {
      return reply.code(400).send({ error: 'cannot deactivate or demote yourself' });
    }

    if (
      (body.is_active !== undefined && typeof body.is_active !== 'boolean') ||
      (body.is_admin !== undefined && typeof body.is_admin !== 'boolean')
    ) {
      return reply.code(400).send({ error: 'is_active, is_admin must be boolean' });
    }

    // 비활성화는 회수 시각(revoked_before)도 찍는다 — 자체 토큰을 가진 앱이 /internal/account 로 따라온다.
    const { rows } = await query<{ id: number; email: string; is_active: boolean; is_admin: boolean }>(
      `UPDATE users SET
         is_active = COALESCE($2::boolean, is_active),
         is_admin = COALESCE($3::boolean, is_admin),
         revoked_before = CASE WHEN $2::boolean IS FALSE THEN now() ELSE revoked_before END
       WHERE id = $1
       RETURNING id, email, is_active, is_admin`,
      [id, body.is_active ?? null, body.is_admin ?? null],
    );
    if (rows.length === 0) return reply.code(404).send({ error: 'user not found' });

    // Deactivation takes effect immediately anyway (session lookup checks
    // is_active), but drop the sessions so the table reflects reality.
    if (body.is_active === false) {
      await query('DELETE FROM sessions WHERE user_id = $1', [id]);
      revokeAccount(String(id)); // OP 세션·grant·토큰
    }
    if (body.is_active !== undefined) {
      await logAdminEvent(admin, body.is_active ? 'user.activate' : 'user.deactivate', rows[0].email, { user_id: id }, req.ip);
    }
    if (body.is_admin !== undefined) {
      await logAdminEvent(admin, 'user.role', rows[0].email, { user_id: id, is_admin: body.is_admin }, req.ip);
    }
    return rows[0];
  });

  // 세션 종료: gatehouse 세션 + OP 세션·grant 를 지우고 회수 시각을 찍는다(앱 자체 세션·토큰도 1분 안에 끊긴다).
  app.delete('/api/admin/users/:id/sessions', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const id = parseInt((req.params as { id: string }).id, 10);
    const target = await query<{ email: string }>(
      'UPDATE users SET revoked_before = now() WHERE id = $1 RETURNING email',
      [id],
    );
    if (target.rows.length === 0) return reply.code(404).send({ error: 'user not found' });
    const { rowCount } = await query('DELETE FROM sessions WHERE user_id = $1', [id]);
    const oidcRevoked = revokeAccount(String(id));
    await logAdminEvent(admin, 'user.sessions.revoke', target.rows[0].email, { user_id: id, sessions: rowCount ?? 0, oidc: oidcRevoked }, req.ip);
    return { revoked: rowCount ?? 0 };
  });

  app.get('/api/admin/clients', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const { rows } = await query(
      `SELECT id, client_id, name, redirect_uris, grant_types, token_endpoint_auth_method, created_at
       FROM oidc_clients ORDER BY id`,
    );
    return rows;
  });

  app.post('/api/admin/clients', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const body = req.body as ClientBody;
    if (!body.client_id || !body.name) {
      return reply.code(400).send({ error: 'client_id, name required' });
    }
    const optErr = validateClientOptions(body);
    if (optErr) return reply.code(400).send({ error: optErr });

    const grantTypes = body.grant_types ?? ['authorization_code'];
    const authMethod = body.token_endpoint_auth_method ?? 'client_secret_post';
    // redirect_uris only matter for the authorization_code redirect; a
    // device-flow-only client legitimately has none.
    const redirectUris = body.redirect_uris ?? [];
    if (grantTypes.includes('authorization_code') && redirectUris.length === 0) {
      return reply
        .code(400)
        .send({ error: 'redirect_uris required for authorization_code clients' });
    }

    // A secret is always stored (NOT NULL column) but only meaningful — and
    // only revealed — for confidential clients.
    const secret = randomBytes(32).toString('base64url');
    try {
      const { rows } = await query(
        `INSERT INTO oidc_clients (client_id, client_secret, name, redirect_uris, grant_types, token_endpoint_auth_method)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, client_id, name, redirect_uris, grant_types, token_endpoint_auth_method, created_at`,
        [body.client_id, secret, body.name, redirectUris, grantTypes, authMethod],
      );
      // 감사 로그에는 설정만 남긴다. 시크릿은 절대 넣지 않는다.
      await logAdminEvent(admin, 'client.create', body.client_id, { name: body.name, redirect_uris: redirectUris, grant_types: grantTypes, token_endpoint_auth_method: authMethod }, req.ip);
      // The secret is returned exactly once, at creation.
      return authMethod === 'none' ? rows[0] : { ...rows[0], client_secret: secret };
    } catch (err) {
      if ((err as { code?: string }).code === '23505') {
        return reply.code(409).send({ error: 'client_id already exists' });
      }
      throw err;
    }
  });

  app.patch('/api/admin/clients/:id', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const id = parseInt((req.params as { id: string }).id, 10);
    const body = req.body as ClientBody;
    const optErr = validateClientOptions(body);
    if (optErr) return reply.code(400).send({ error: optErr });

    // Validate the *effective* combination before touching the row.
    const current = await query<{ redirect_uris: string[]; grant_types: string[] }>(
      'SELECT redirect_uris, grant_types FROM oidc_clients WHERE id = $1',
      [id],
    );
    if (current.rows.length === 0) return reply.code(404).send({ error: 'client not found' });
    const effGrants = body.grant_types ?? current.rows[0].grant_types;
    const effUris = body.redirect_uris ?? current.rows[0].redirect_uris;
    if (effGrants.includes('authorization_code') && effUris.length === 0) {
      return reply
        .code(400)
        .send({ error: 'authorization_code clients need at least one redirect_uri' });
    }

    const { rows } = await query(
      `UPDATE oidc_clients SET
         name = COALESCE($2, name),
         redirect_uris = COALESCE($3, redirect_uris),
         grant_types = COALESCE($4, grant_types),
         token_endpoint_auth_method = COALESCE($5, token_endpoint_auth_method)
       WHERE id = $1
       RETURNING id, client_id, name, redirect_uris, grant_types, token_endpoint_auth_method, created_at`,
      [
        id,
        body.name ?? null,
        body.redirect_uris ?? null,
        body.grant_types ?? null,
        body.token_endpoint_auth_method ?? null,
      ],
    );
    if (rows.length === 0) return reply.code(404).send({ error: 'client not found' });
    // 바꾸겠다고 보낸 필드만 남긴다(시크릿은 이 API 로 바뀌지 않는다).
    const changed: Record<string, unknown> = {};
    for (const k of ['name', 'redirect_uris', 'grant_types', 'token_endpoint_auth_method'] as const) {
      if (body[k] !== undefined) changed[k] = body[k];
    }
    await logAdminEvent(admin, 'client.update', String(rows[0].client_id), changed, req.ip);
    return rows[0];
  });

  app.delete('/api/admin/clients/:id', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const id = parseInt((req.params as { id: string }).id, 10);
    const { rows } = await query<{ client_id: string; name: string }>(
      'DELETE FROM oidc_clients WHERE id = $1 RETURNING client_id, name',
      [id],
    );
    if (rows.length === 0) return reply.code(404).send({ error: 'client not found' });
    await logAdminEvent(admin, 'client.delete', rows[0].client_id, { name: rows[0].name }, req.ip);
    return { deleted: true };
  });

  app.get('/api/admin/events', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const { email, limit } = req.query as { email?: string; limit?: string };
    const n = Math.min(parseInt(limit ?? '200', 10) || 200, 1000);
    const { rows } = email
      ? await query(
          `SELECT id, email, event, detail, ip, user_agent, created_at
           FROM login_events WHERE email ILIKE $1 ORDER BY id DESC LIMIT $2`,
          [`%${email}%`, n],
        )
      : await query(
          `SELECT id, email, event, detail, ip, user_agent, created_at
           FROM login_events ORDER BY id DESC LIMIT $1`,
          [n],
        );
    return rows;
  });

  // ---- 관리자 작업 감사 로그 ----
  app.get('/api/admin/audit', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const { q, limit } = req.query as { q?: string; limit?: string };
    const n = Math.min(parseInt(limit ?? '200', 10) || 200, 1000);
    const { rows } = q
      ? await query(
          `SELECT id, actor_email, action, target, detail, ip, created_at
           FROM admin_events WHERE actor_email ILIKE $1 OR target ILIKE $1 OR action ILIKE $1
           ORDER BY id DESC LIMIT $2`,
          [`%${q}%`, n],
        )
      : await query(
          `SELECT id, actor_email, action, target, detail, ip, created_at
           FROM admin_events ORDER BY id DESC LIMIT $1`,
          [n],
        );
    return rows;
  });

  // ---- 앱별 접근 정책 ----
  // 알려진 앱 = 최근 forward-auth 판정에 나온 호스트 + OIDC 클라이언트 + 정책이 있는 키.
  app.get('/api/admin/apps', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const [hosts, clients, policies, access] = await Promise.all([
      query<{ host: string }>(
        `SELECT DISTINCT lower(host) AS host FROM zt_checks
         WHERE created_at > now() - interval '30 days' AND host NOT LIKE 'oidc:%' AND host <> ''`,
      ),
      query<{ client_id: string; name: string }>('SELECT client_id, name FROM oidc_clients ORDER BY id'),
      query<{ app_key: string; mode: string; note: string | null; updated_at: Date }>(
        'SELECT app_key, mode, note, updated_at FROM app_policies',
      ),
      query<{ app_key: string; id: number; email: string; name: string; is_active: boolean }>(
        `SELECT a.app_key, u.id, u.email, u.name, u.is_active
         FROM app_access a JOIN users u ON u.id = a.user_id ORDER BY u.email`,
      ),
    ]);
    type App = {
      app_key: string;
      kind: 'host' | 'oidc';
      name: string;
      mode: string;
      note: string | null;
      updated_at: Date | null;
      users: { id: number; email: string; name: string; is_active: boolean }[];
    };
    const apps = new Map<string, App>();
    const ensure = (key: string, name?: string): App => {
      let a = apps.get(key);
      if (!a) {
        a = { app_key: key, kind: key.startsWith('oidc:') ? 'oidc' : 'host', name: name ?? '', mode: 'all', note: null, updated_at: null, users: [] };
        apps.set(key, a);
      } else if (name && !a.name) a.name = name;
      return a;
    };
    for (const c of clients.rows) ensure(oidcAppKey(c.client_id), c.name);
    for (const h of hosts.rows) if (isValidAppKey(h.host)) ensure(h.host);
    for (const p of policies.rows) Object.assign(ensure(p.app_key), { mode: p.mode, note: p.note, updated_at: p.updated_at });
    for (const u of access.rows) ensure(u.app_key).users.push({ id: u.id, email: u.email, name: u.name, is_active: u.is_active });
    return [...apps.values()].sort((a, b) => a.app_key.localeCompare(b.app_key));
  });

  /** 경로의 :key 를 검증해 돌려준다. 잘못됐으면 400 을 보내고 null. */
  const appKeyParam = (req: FastifyRequest, reply: FastifyReply): string | null => {
    const key = normalizeAppKey((req.params as { key: string }).key);
    if (!isValidAppKey(key)) {
      reply.code(400).send({ error: 'app_key must be a host (e.g. vault.datasee.co.kr) or oidc:<client_id>' });
      return null;
    }
    return key;
  };

  app.put('/api/admin/apps/:key', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const key = appKeyParam(req, reply);
    if (!key) return;
    const body = (req.body ?? {}) as { mode?: string; note?: string | null };
    if (body.mode !== 'all' && body.mode !== 'restricted') {
      return reply.code(400).send({ error: "mode must be 'all' or 'restricted'" });
    }
    if (body.note !== undefined && body.note !== null && typeof body.note !== 'string') {
      return reply.code(400).send({ error: 'note must be a string' });
    }
    const { rows } = await query(
      `INSERT INTO app_policies (app_key, mode, note) VALUES ($1, $2, $3)
       ON CONFLICT (app_key) DO UPDATE SET
         mode = EXCLUDED.mode,
         note = CASE WHEN $4 THEN EXCLUDED.note ELSE app_policies.note END,
         updated_at = now()
       RETURNING app_key, mode, note, updated_at`,
      [key, body.mode, body.note ?? null, body.note !== undefined],
    );
    invalidateAppAccess(key);
    await logAdminEvent(admin, 'app.policy', key, { mode: body.mode, ...(body.note !== undefined ? { note: body.note } : {}) }, req.ip);
    return rows[0];
  });

  app.put('/api/admin/apps/:key/users/:userId', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const key = appKeyParam(req, reply);
    if (!key) return;
    const userId = parseInt((req.params as { userId: string }).userId, 10);
    const user = await query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) return reply.code(404).send({ error: 'user not found' });
    // 허용 목록은 제한 모드로 바꾸기 전에 미리 채울 수 있어야 한다 — 정책 행이 없으면 'all' 로 만들어 둔다.
    await query(`INSERT INTO app_policies (app_key) VALUES ($1) ON CONFLICT DO NOTHING`, [key]);
    const { rowCount } = await query(
      'INSERT INTO app_access (app_key, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [key, userId],
    );
    invalidateAppAccess(key);
    if (rowCount) await logAdminEvent(admin, 'app.user.add', key, { user_id: userId, email: user.rows[0].email }, req.ip);
    return { added: Boolean(rowCount) };
  });

  app.delete('/api/admin/apps/:key/users/:userId', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const key = appKeyParam(req, reply);
    if (!key) return;
    const userId = parseInt((req.params as { userId: string }).userId, 10);
    const { rowCount } = await query('DELETE FROM app_access WHERE app_key = $1 AND user_id = $2', [key, userId]);
    invalidateAppAccess(key);
    if (rowCount) {
      const user = await query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId]);
      await logAdminEvent(admin, 'app.user.remove', key, { user_id: userId, email: user.rows[0]?.email ?? null }, req.ip);
    }
    return { removed: Boolean(rowCount) };
  });

  // ---- 제로트러스트(ward 디바이스 상태 판정) ----
  app.get('/api/admin/zt/config', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const z = config.zt;
    return {
      mode: z.mode,
      ward_url: z.wardUrl,
      ward_public_url: z.wardPublicUrl,
      secret_set: Boolean(z.wardSecret),
      fail_open: z.failOpen,
      cache_sec: z.cacheSec,
      timeout_ms: z.timeoutMs,
      exempt_emails: z.exemptEmails,
      exempt_hosts: z.exemptHosts,
      // 전역 모드와 별개로 enforce 가 적용되는 사용자(전역이 off 면 효과 없음).
      enforce_emails: [...zeroTrust.enforceEmails],
      enforce_count: zeroTrust.enforceEmails.length,
      oidc_exempt_clients: z.oidcExemptClients,
    };
  });

  app.get('/api/admin/zt/checks', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const { email, limit, denied } = req.query as { email?: string; limit?: string; denied?: string };
    const n = Math.min(parseInt(limit ?? '200', 10) || 200, 1000);
    const where: string[] = [];
    const params: unknown[] = [];
    if (email) {
      params.push(`%${email}%`);
      where.push(`email ILIKE $${params.length}`);
    }
    if (denied === '1') where.push('allowed = false');
    params.push(n);
    const { rows } = await query(
      `SELECT id, email, host, ip, verdict, device_id, device_hostname, mode, allowed, error, created_at
       FROM zt_checks ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
       ORDER BY id DESC LIMIT $${params.length}`,
      params,
    );
    return rows;
  });

  app.get('/api/admin/zt/stats', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const { rows } = await query(
      `SELECT verdict, count(*)::int AS n, bool_or(NOT allowed) AS any_denied
       FROM zt_checks WHERE created_at > now() - interval '24 hours' GROUP BY verdict`,
    );
    return { last_24h: rows };
  });
}
