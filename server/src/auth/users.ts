import { query } from '../db/pool.js';
import { config } from '../config.js';
import type { GoogleIdentity } from './google.js';

export interface UserRow {
  id: number;
  email: string;
  name: string;
  hd: string;
  picture: string | null;
  is_active: boolean;
  is_admin: boolean;
}

/** JIT provisioning: first Google sign-in from an allowed domain creates the user. */
export async function upsertUser(identity: GoogleIdentity): Promise<UserRow> {
  const bootstrapAdmin = config.adminEmails.includes(identity.email.toLowerCase());
  const { rows } = await query<UserRow>(
    `INSERT INTO users (google_sub, email, hd, name, picture, is_admin, last_login_at)
     VALUES ($1, $2, $3, $4, $5, $6, now())
     ON CONFLICT (google_sub) DO UPDATE SET
       email = EXCLUDED.email,
       hd = EXCLUDED.hd,
       name = EXCLUDED.name,
       picture = EXCLUDED.picture,
       is_admin = users.is_admin OR EXCLUDED.is_admin,
       last_login_at = now()
     RETURNING id, email, name, hd, picture, is_active, is_admin`,
    [identity.sub, identity.email, identity.hd, identity.name, identity.picture, bootstrapAdmin],
  );
  return rows[0];
}

export async function logEvent(
  event: 'login' | 'logout' | 'denied',
  email: string,
  opts: { userId?: number; detail?: string; ip?: string; userAgent?: string } = {},
): Promise<void> {
  await query(
    `INSERT INTO login_events (user_id, email, event, detail, ip, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [opts.userId ?? null, email, event, opts.detail ?? null, opts.ip ?? null, opts.userAgent ?? null],
  ).catch((err) => console.error('audit log failed', err));
}
