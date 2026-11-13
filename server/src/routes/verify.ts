import { randomBytes } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { baseUrl, config } from '../config.js';
import { SESSION_COOKIE, getSessionUser, type SessionUser } from '../auth/session.js';
import { clientIp, zeroTrust } from '../zt/index.js';
import { deniedCsp, deniedPage, parseDeniedReason, parseDeniedVerdict, type ZtResult } from '../zt/zt.js';
import { appDeniedPage, isAppAllowed } from '../auth/appAccess.js';
import { safeRedirect } from './auth.js';

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

/**
 * 통과(200) 응답에 항상 싣는다. '1' = 소프트 호스트라 통과시켰지만 기기 판정은 거부였다 — 앱이 이 세션의 권한을 줄여야 한다.
 * 그 외(준수·면제·monitor·판정 꺼짐)는 '0'. 값이 늘 있어야 nginx 가 클라이언트가 보낸 같은 이름의 헤더를 덮어쓴다.
 */
function setRestrictedHeader(reply: FastifyReply, zt: ZtResult | null): void {
  reply.header('X-Auth-Device-Restricted', zt?.restricted ? '1' : '0');
}

/** 기기 거부 사유 헤더. nginx 가 이 둘을 /auth/denied 의 v·r 쿼리로 옮긴다(안내 페이지는 공인 IP 로 불려 스스로 판정할 수 없다). */
function setDeniedHeaders(reply: FastifyReply, zt: ZtResult): void {
  reply.header('X-Auth-Denied', zt.verdict);
  if (zt.reason) reply.header('X-Auth-Denied-Reason', zt.reason);
}

/** 기기 거부 안내 페이지를 보낸다. 인라인 script·style 은 응답마다 새 nonce 로만 허용한다. */
function sendDeniedPage(
  reply: FastifyReply,
  opts: { verdict: string; reason?: string | null; hostname?: string | null; rd?: string | null },
): FastifyReply {
  const nonce = randomBytes(16).toString('base64');
  return reply
    .code(403)
    .header('Content-Security-Policy', deniedCsp(nonce))
    .header('Cache-Control', 'no-store')
    .header('X-Content-Type-Options', 'nosniff')
    .header('X-Frame-Options', 'DENY')
    .header('Referrer-Policy', 'no-referrer')
    .type('text/html; charset=utf-8')
    .send(deniedPage({ ...opts, wardUrl: config.zt.wardPublicUrl, nonce }));
}

/** 쿼리 값이 같은 이름으로 여러 번 오면 배열이 된다. 그런 건 받지 않는다. */
function one(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
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
    // 앱 접근 정책이 기기 판정보다 먼저다(권한이 없으면 기기를 고쳐도 소용없다). 신원 헤더는 싣지 않는다.
    if (!(await isAppAllowed(protectedHost(req), user.id))) {
      reply.header('X-Auth-Denied', 'app_access');
      return reply.code(403).send();
    }
    const zt = await ztCheck(req, user);
    setIdentityHeaders(reply, user);
    setDeviceHeaders(reply, zt);
    if (zt && !zt.allowed) {
      // nginx 는 auth_request 의 본문을 버리므로 안내는 /auth/denied 가 맡는다. 헤더로 사유만 넘긴다.
      setDeniedHeaders(reply, zt);
      return reply.code(403).send();
    }
    setRestrictedHeader(reply, zt);
    return reply.code(200).send();
  });

  // Traefik forwardAuth: non-2xx responses (incl. redirects) are passed to the client.
  app.get('/auth/traefik', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    if (user) {
      const host = protectedHost(req);
      if (!(await isAppAllowed(host, user.id))) {
        return reply
          .code(403)
          .header('X-Auth-Denied', 'app_access')
          .type('text/html; charset=utf-8')
          .send(appDeniedPage({ app: host, email: user.email }));
      }
      const zt = await ztCheck(req, user);
      if (zt && !zt.allowed) {
        // Traefik 은 이 응답을 그대로 브라우저에 준다. 앱 호스트에서 보이는 페이지라 "다시 시도"는 원래 주소(같은 판정 경로)로 간다.
        setDeniedHeaders(reply, zt);
        return sendDeniedPage(reply, {
          verdict: zt.verdict,
          reason: zt.reason,
          hostname: zt.device?.hostname,
          rd: safeRedirect(originalUrl(req) ?? undefined),
        });
      }
      setIdentityHeaders(reply, user);
      setDeviceHeaders(reply, zt);
      setRestrictedHeader(reply, zt);
      return reply.code(200).send();
    }
    const rd = originalUrl(req);
    const login = new URL('/login', baseUrl());
    if (rd) login.searchParams.set('rd', rd);
    return reply.redirect(login.href);
  });

  /**
   * 거부 안내 페이지(앱 접근 거부·기기 거부 공용). nginx 에서 `error_page 403 = @zt_denied;` →
   * `return 302 https://auth.datasee.co.kr/auth/denied?rd=…&v=<X-Auth-Denied>&r=<X-Auth-Denied-Reason>` 로 보낸다.
   *
   * 이 페이지는 기기 판정을 다시 하지 않는다. 인증 호스트는 공인 인터넷으로 들어오므로 여기서 본 요청 IP 는
   * 에이전트가 보고한 VPN IP 와 절대 맞지 않는다(늘 no_device 가 나와 엉뚱한 사유를 보여 주고, 자동 복귀도 못 했다).
   * 사유는 /auth/verify 가 실제로 내린 판정을 nginx 가 v·r 로 옮겨 준 것만 쓰고, 허용 목록 밖의 값은 버린다.
   * 통과로 바뀌었는지는 원래 주소(rd)로 돌아가 보는 수밖에 없다 — "다시 시도" 버튼과 자동 재시도가 그 일을 한다.
   * 앱 접근 정책은 IP 와 무관해 여기서 다시 봐도 된다. rd 는 로그인 때와 같은 검증을 거친 것만 쓴다(오픈 리다이렉트 방지).
   */
  app.get('/auth/denied', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;
    const q = req.query as Record<string, unknown>;
    const rd = safeRedirect(one(q.rd));
    const v = parseDeniedVerdict(one(q.v));
    const reason = parseDeniedReason(one(q.r));
    // 절대 주소 rd 면 그 호스트가 거부된 앱이다. 상대 경로면 gatehouse 자신이라 헤더에서 읽는다.
    const host = rd && !rd.startsWith('/') ? new URL(rd).host.toLowerCase() : protectedHost(req);
    const appDenied = () =>
      reply
        .code(403)
        .header('X-Auth-Denied', 'app_access')
        .type('text/html; charset=utf-8')
        .send(appDeniedPage({ app: host, email: user?.email }));

    if (user && !(await isAppAllowed(host, user.id))) return appDenied();
    if (v === 'app_access' || (v === null && zeroTrust.mode === 'off')) {
      // 여기 온 이유가 앱 접근 거부(판정이 꺼져 있고 v 가 없으면 그것뿐이다)인데 지금은 허용이다 — 관리자가 권한을 추가했다.
      if (user && rd) return reply.redirect(rd);
      if (v === 'app_access') return appDenied();
    }
    // v 가 없거나 모르는 값이면 '아직 확인하지 못함'으로 안내한다(v 를 넘기지 않는 옛 nginx 설정도 여기로 온다).
    const verdict = v ?? 'unknown';
    return sendDeniedPage(reply, { verdict, reason: verdict === 'unknown' ? reason : null, rd });
  });
}
