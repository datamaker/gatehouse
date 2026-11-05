import { createHash, randomBytes } from 'node:crypto';
import type { CookieSerializeOptions } from '@fastify/cookie';
import { query } from '../db/pool.js';
import { config, isSecure } from '../config.js';

// `__Host-` would be stricter but forbids the Domain attribute, which we need
// so every subdomain behind forward-auth shares the login.
export const SESSION_COOKIE = isSecure ? '__Secure-gh_session' : 'gh_session';
export const OAUTH_COOKIE = 'gh_oauth';

export function sessionCookieOptions(): CookieSerializeOptions {
  return {
    path: '/',
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
    // 쿠키는 절대 상한만큼 살린다. 실제 만료는 서버(sessions.expires_at)가 결정하므로
    // 쿠키가 더 오래 남아 있어도 해가 없고, 유휴 연장 때 쿠키를 다시 내릴 필요가 없다
    // (forward-auth 의 auth_request 응답은 Set-Cookie 를 브라우저에 전달하지 않는다).
    maxAge: config.sessionMaxHours * 3600,
    ...(config.cookieDomain ? { domain: config.cookieDomain } : {}),
  };
}

export function oauthCookieOptions(): CookieSerializeOptions {
  // Host-only on purpose: the OAuth state never needs to leave gatehouse.
  return { path: '/', httpOnly: true, secure: isSecure, sameSite: 'lax', maxAge: 600 };
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export interface SessionUser {
  id: number;
  email: string;
  name: string;
  hd: string;
  picture: string | null;
  is_admin: boolean;
}

export async function createSession(
  userId: number,
  ip: string | undefined,
  userAgent: string | undefined,
): Promise<string> {
  const token = randomBytes(32).toString('base64url');
  await query(
    `INSERT INTO sessions (token_hash, user_id, expires_at, absolute_expires_at, last_seen_at, ip, user_agent)
     VALUES ($1, $2,
             LEAST(now() + make_interval(hours => $3), now() + make_interval(hours => $4)),
             now() + make_interval(hours => $4),
             now(), $5, $6)`,
    [hashToken(token), userId, config.sessionIdleHours, config.sessionMaxHours, ip ?? null, userAgent ?? null],
  );
  return token;
}

/**
 * 세션 조회 + sliding 연장을 한 번의 왕복으로. 살아 있는 세션이면 마지막 touch 가
 * touch 간격보다 오래됐을 때만 expires_at 을 `now()+유휴` 로 밀되 절대 상한은 넘지 않는다.
 * (WITH 안의 UPDATE 는 결과를 참조하지 않아도 정확히 한 번 실행된다.)
 */
export async function getSessionUser(token: string): Promise<SessionUser | null> {
  const { rows } = await query<SessionUser>(
    `WITH live AS (
       SELECT id, user_id, last_seen_at, absolute_expires_at
       FROM sessions
       WHERE token_hash = $1 AND expires_at > now() AND absolute_expires_at > now()
     ),
     touched AS (
       UPDATE sessions s
       SET last_seen_at = now(),
           expires_at = LEAST(now() + make_interval(hours => $2), live.absolute_expires_at)
       FROM live
       WHERE s.id = live.id
         AND live.last_seen_at < now() - make_interval(mins => $3)
     )
     SELECT u.id, u.email, u.name, u.hd, u.picture, u.is_admin
     FROM live JOIN users u ON u.id = live.user_id
     WHERE u.is_active`,
    [hashToken(token), config.sessionIdleHours, config.sessionTouchMinutes],
  );
  return rows[0] ?? null;
}

export async function destroySession(token: string): Promise<void> {
  await query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(token)]);
}

export function startSessionCleanup(): void {
  const sweep = () =>
    query('DELETE FROM sessions WHERE expires_at < now() OR absolute_expires_at < now()').catch((err) =>
      console.error('session cleanup failed', err),
    );
  sweep();
  setInterval(sweep, 60 * 60 * 1000).unref();
}
