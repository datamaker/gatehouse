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
    maxAge: config.sessionTtlHours * 3600,
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
    `INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent)
     VALUES ($1, $2, now() + make_interval(hours => $3), $4, $5)`,
    [hashToken(token), userId, config.sessionTtlHours, ip ?? null, userAgent ?? null],
  );
  return token;
}

export async function getSessionUser(token: string): Promise<SessionUser | null> {
  const { rows } = await query<SessionUser>(
    `SELECT u.id, u.email, u.name, u.hd, u.picture, u.is_admin
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now() AND u.is_active`,
    [hashToken(token)],
  );
  return rows[0] ?? null;
}

export async function destroySession(token: string): Promise<void> {
  await query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(token)]);
}

export function startSessionCleanup(): void {
  const sweep = () =>
    query('DELETE FROM sessions WHERE expires_at < now()').catch((err) =>
      console.error('session cleanup failed', err),
    );
  sweep();
  setInterval(sweep, 60 * 60 * 1000).unref();
}
