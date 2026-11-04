import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { baseUrl, config } from '../config.js';
import { SESSION_COOKIE, getSessionUser, type SessionUser } from '../auth/session.js';
import { clientIp, zeroTrust } from '../zt/index.js';
import { deniedPage, type ZtResult } from '../zt/zt.js';

function setIdentityHeaders(reply: FastifyReply, user: SessionUser): void {
  reply.header('X-Auth-User', String(user.id));
  reply.header('X-Auth-Email', user.email);
  // HTTP headers are latin1-only; Korean names would crash the response.
  reply.header('X-Auth-Name', encodeURIComponent(user.name));
}

function setDeviceHeaders(reply: FastifyReply, zt: ZtResult | null): void {
  if (!zt || zt.mode === 'off') return;
  reply.header('X-Auth-Device', zt.device?.id ?? '');
  reply.header('X-Auth-Device-Status', zt.verdict);
}

/** Rebuilds the URL the user originally requested, from forward-auth headers. */
function originalUrl(req: FastifyRequest): string | null {
  const host = req.headers['x-forwarded-host'] as string | undefined;
  if (!host) return null;
  const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? 'https';
  const uri = (req.headers['x-forwarded-uri'] as string | undefined) ?? '/';
  return `${proto}://${host}${uri}`;
}

/** forward-auth 가 보호하는 앱의 호스트. nginx 는 X-Forwarded-Host 를, Traefik 은 X-Forwarded-Host 를 준다. */
function protectedHost(req: FastifyRequest): string {
  const h = (req.headers['x-forwarded-host'] as string | undefined) ?? (req.headers['x-original-host'] as string | undefined);
  return (h ?? req.hostname ?? '').split(',')[0].trim().toLowerCase();
}

/**
 * 제로트러스트 판정. 세션이 확인된 뒤에 부른다. off 면 null.
 * 요청마다 불리지만 ZeroTrust 가 email+ip 로 60초 캐시하므로 ward 는 분당 1회만 맞는다(기록은 앱마다 분당 1건).
 */
async function ztCheck(req: FastifyRequest, user: SessionUser): Promise<ZtResult | null> {
  if (zeroTrust.mode === 'off') return null;
  return zeroTrust.check({ email: user.email, host: protectedHost(req), ip: clientIp(req) });
}

export function registerVerifyRoutes(app: FastifyInstance): void {
  // nginx `auth_request`: subrequests must get 2xx/401/403, never redirects.
  // Pair with `error_page 401 = @gatehouse_login;` in the nginx config, and
  // `error_page 403 = @zt_denied;` to show /auth/denied for device rejections.
  app.get('/auth/verify', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    if (!user) return reply.code(401).send();
    const zt = await ztCheck(req, user);
    setIdentityHeaders(reply, user);
    setDeviceHeaders(reply, zt);
    if (zt && !zt.allowed) {
      // nginx 는 auth_request 의 본문을 버리므로 안내는 /auth/denied 가 맡는다. 헤더로 사유만 넘긴다.
      reply.header('X-Auth-Denied', zt.verdict);
      return reply.code(403).send();
    }
    return reply.code(200).send();
  });

  // Traefik forwardAuth: non-2xx responses (incl. redirects) are passed to the client.
  app.get('/auth/traefik', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    if (user) {
      const zt = await ztCheck(req, user);
      if (zt && !zt.allowed) {
        return reply
          .code(403)
          .type('text/html; charset=utf-8')
          .send(deniedPage({ verdict: zt.verdict, wardUrl: config.zt.wardPublicUrl, hostname: zt.device?.hostname }));
      }
      setIdentityHeaders(reply, user);
      setDeviceHeaders(reply, zt);
      return reply.code(200).send();
    }
    const rd = originalUrl(req);
    const login = new URL('/login', baseUrl());
    if (rd) login.searchParams.set('rd', rd);
    return reply.redirect(login.href);
  });

  /**
   * 기기 거부 안내 페이지. nginx 에서 `error_page 403 = @zt_denied;` →
   * `return 302 https://auth.datasee.co.kr/auth/denied?rd=…` 로 보낸다.
   * 세션이 있으면 지금 상태로 다시 판정해 보여 준다(캐시 TTL 안이면 같은 결과).
   */
  app.get('/auth/denied', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    let verdict = 'unknown';
    let hostname: string | null = null;
    if (user && zeroTrust.mode !== 'off') {
      const rd = (req.query as { rd?: string }).rd;
      let host = protectedHost(req);
      try {
        if (rd) host = new URL(rd).host.toLowerCase();
      } catch {
        /* rd 가 URL 이 아니면 무시 */
      }
      const zt = await zeroTrust.check({ email: user.email, host, ip: clientIp(req) });
      if (zt.allowed && rd) return reply.redirect(rd); // 그 사이 준수로 바뀌었으면 바로 돌려보낸다
      verdict = zt.verdict;
      hostname = zt.device?.hostname ?? null;
    }
    return reply
      .code(403)
      .type('text/html; charset=utf-8')
      .send(deniedPage({ verdict, wardUrl: config.zt.wardPublicUrl, hostname }));
  });
}
