import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { baseUrl } from '../config.js';
import { SESSION_COOKIE, getSessionUser, type SessionUser } from '../auth/session.js';

function setIdentityHeaders(reply: FastifyReply, user: SessionUser): void {
  reply.header('X-Auth-User', String(user.id));
  reply.header('X-Auth-Email', user.email);
  // HTTP headers are latin1-only; Korean names would crash the response.
  reply.header('X-Auth-Name', encodeURIComponent(user.name));
}

/** Rebuilds the URL the user originally requested, from forward-auth headers. */
function originalUrl(req: FastifyRequest): string | null {
  const host = req.headers['x-forwarded-host'] as string | undefined;
  if (!host) return null;
  const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? 'https';
  const uri = (req.headers['x-forwarded-uri'] as string | undefined) ?? '/';
  return `${proto}://${host}${uri}`;
}

export function registerVerifyRoutes(app: FastifyInstance): void {
  // nginx `auth_request`: subrequests must get 2xx/401/403, never redirects.
  // Pair with `error_page 401 = @gatehouse_login;` in the nginx config.
  app.get('/auth/verify', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    if (!user) return reply.code(401).send();
    setIdentityHeaders(reply, user);
    return reply.code(200).send();
  });

  // Traefik forwardAuth: non-2xx responses (incl. redirects) are passed to the client.
  app.get('/auth/traefik', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    if (user) {
      setIdentityHeaders(reply, user);
      return reply.code(200).send();
    }
    const rd = originalUrl(req);
    const login = new URL('/login', baseUrl());
    if (rd) login.searchParams.set('rd', rd);
    return reply.redirect(login.href);
  });
}
