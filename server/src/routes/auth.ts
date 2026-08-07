import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config, baseUrl } from '../config.js';
import { buildAuthUrl, handleCallback } from '../auth/google.js';
import { upsertUser, logEvent } from '../auth/users.js';
import {
  SESSION_COOKIE,
  OAUTH_COOKIE,
  createSession,
  destroySession,
  getSessionUser,
  sessionCookieOptions,
  oauthCookieOptions,
} from '../auth/session.js';

/** Rejects open redirects: only relative paths or hosts under redirectDomains. */
export function safeRedirect(rd: string | undefined): string | null {
  if (!rd) return null;
  if (rd.startsWith('/') && !rd.startsWith('//')) return rd;
  let url: URL;
  try {
    url = new URL(rd);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const host = url.hostname.toLowerCase();
  const ok = config.redirectDomains.some((d) => host === d || host.endsWith(`.${d}`));
  return ok ? url.href : null;
}

async function currentUser(req: FastifyRequest) {
  const token = req.cookies[SESSION_COOKIE];
  return token ? getSessionUser(token) : null;
}

function clientInfo(req: FastifyRequest) {
  return {
    ip: (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip,
    userAgent: req.headers['user-agent'],
  };
}

export function registerAuthRoutes(app: FastifyInstance): void {
  app.get('/login', async (req, reply) => {
    const { rd } = req.query as { rd?: string };
    const { url, state, codeVerifier } = await buildAuthUrl();
    const payload = Buffer.from(
      JSON.stringify({ state, codeVerifier, rd: safeRedirect(rd) ?? '/' }),
    ).toString('base64url');
    return reply
      .setCookie(OAUTH_COOKIE, payload, { ...oauthCookieOptions(), signed: true })
      .redirect(url);
  });

  app.get('/callback', async (req, reply) => {
    const raw = req.cookies[OAUTH_COOKIE];
    const unsigned = raw ? req.unsignCookie(raw) : null;
    if (!unsigned?.valid || !unsigned.value) {
      return reply.code(400).send('login flow expired; start again at /login');
    }
    const { state, codeVerifier, rd } = JSON.parse(
      Buffer.from(unsigned.value, 'base64url').toString(),
    ) as { state: string; codeVerifier: string; rd: string };
    reply.clearCookie(OAUTH_COOKIE, { path: '/' });

    const { ip, userAgent } = clientInfo(req);
    let identity;
    try {
      identity = await handleCallback(
        new URL(req.url, baseUrl()),
        state,
        codeVerifier,
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      req.log.warn({ detail }, 'login denied');
      await logEvent('denied', '', { detail, ip, userAgent });
      return reply.code(403).send(`sign-in denied: ${detail}`);
    }

    const user = await upsertUser(identity);
    if (!user.is_active) {
      await logEvent('denied', user.email, { userId: user.id, detail: 'deactivated', ip, userAgent });
      return reply.code(403).send('account is deactivated');
    }

    const token = await createSession(user.id, ip, userAgent);
    await logEvent('login', user.email, { userId: user.id, ip, userAgent });
    return reply.setCookie(SESSION_COOKIE, token, sessionCookieOptions()).redirect(rd || '/');
  });

  const logout = async (req: FastifyRequest, reply: FastifyReply) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) {
      const user = await getSessionUser(token);
      await destroySession(token);
      if (user) await logEvent('logout', user.email, { userId: user.id, ...clientInfo(req) });
    }
    return reply
      .clearCookie(SESSION_COOKIE, { ...sessionCookieOptions(), maxAge: undefined })
      .redirect('/');
  };
  app.get('/logout', logout);
  app.post('/logout', logout);

  app.get('/api/me', async (req, reply) => {
    const user = await currentUser(req);
    if (!user) return reply.code(401).send({ error: 'not signed in' });
    return user;
  });
}
