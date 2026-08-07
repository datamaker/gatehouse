import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { query } from '../db/pool.js';
import { SESSION_COOKIE, getSessionUser, type SessionUser } from '../auth/session.js';

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

    const { rows } = await query(
      `UPDATE users SET
         is_active = COALESCE($2, is_active),
         is_admin = COALESCE($3, is_admin)
       WHERE id = $1
       RETURNING id, email, is_active, is_admin`,
      [id, body.is_active ?? null, body.is_admin ?? null],
    );
    if (rows.length === 0) return reply.code(404).send({ error: 'user not found' });

    // Deactivation takes effect immediately anyway (session lookup checks
    // is_active), but drop the sessions so the table reflects reality.
    if (body.is_active === false) {
      await query('DELETE FROM sessions WHERE user_id = $1', [id]);
    }
    return rows[0];
  });

  app.delete('/api/admin/users/:id/sessions', async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const id = parseInt((req.params as { id: string }).id, 10);
    const { rowCount } = await query('DELETE FROM sessions WHERE user_id = $1', [id]);
    return { revoked: rowCount ?? 0 };
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
}
