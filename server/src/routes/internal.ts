import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { query } from '../db/pool.js';

/** 길이가 달라도 시간이 새지 않게 해시끼리 비교한다. */
function secretMatches(given: unknown, expected: string): boolean {
  if (typeof given !== 'string' || !given) return false;
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * 계정 상태 조회 (회수 전파). 계약: ~/datasee/zt-contracts-2026-11-13.md A 절.
 *
 *   GET /internal/account?email=<이메일>     헤더 X-Gatehouse-Secret
 *   200 {"email","active","revoked_before"}  · 404 {"active":false} 모르는 이메일 · 401 시크릿 불일치
 *
 * 자체 세션·토큰을 가진 앱(vault, lookout, mailroom, pgsearch, notebook CLI, opentunnel)이 60초 캐시로 묻는다.
 * 시크릿(GATEHOUSE_INTERNAL_SECRET)이 없으면 라우트를 등록하지 않는다 — 요청은 404 가 된다.
 */
export function registerInternalRoutes(app: FastifyInstance, secret: string): void {
  if (!secret) return;

  app.get('/internal/account', async (req, reply) => {
    if (!secretMatches(req.headers['x-gatehouse-secret'], secret)) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    const email = (req.query as { email?: unknown }).email;
    if (typeof email !== 'string' || !email.trim()) {
      return reply.code(400).send({ error: 'email required' });
    }
    const { rows } = await query<{ email: string; is_active: boolean; revoked_before: Date | null }>(
      'SELECT email, is_active, revoked_before FROM users WHERE lower(email) = lower($1) LIMIT 1',
      [email.trim()],
    );
    const u = rows[0];
    reply.header('Cache-Control', 'no-store');
    if (!u) return reply.code(404).send({ active: false });
    return {
      email: u.email,
      active: u.is_active,
      revoked_before: u.revoked_before ? u.revoked_before.toISOString() : null,
    };
  });
}
