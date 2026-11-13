import type { FastifyInstance, FastifyRequest } from 'fastify';
import { config, baseUrl } from '../config.js';
import { buildAuthUrl, handleCallback } from '../auth/google.js';
import { upsertUser, logEvent } from '../auth/users.js';
import { checkRedirect } from '../auth/redirect.js';
import { revokeAccount } from '../oidc/adapter.js';
import {
  SESSION_COOKIE,
  OAUTH_COOKIE,
  createSession,
  destroySession,
  getSessionUser,
  sessionCookieOptions,
  oauthCookieOptions,
} from '../auth/session.js';

/** Rejects open redirects: only same-origin relative paths or hosts under redirectDomains. */
export function safeRedirect(rd: string | undefined): string | null {
  return checkRedirect(rd, baseUrl(), config.redirectDomains);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/**
 * 로그아웃 확인 페이지. 사내 앱들이 `<a href="https://auth…/logout">` 로 걸어 두었으므로 GET 은 살려 두되,
 * GET 만으로는 아무것도 바꾸지 않는다(이미지 태그·링크 한 번으로 남을 로그아웃시키는 CSRF 방지). 실제 로그아웃은 이 폼의 POST.
 */
function logoutPage(email: string, rd: string | null): string {
  const action = rd ? `/logout?rd=${encodeURIComponent(rd)}` : '/logout';
  const back = rd ?? '/';
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>gatehouse — 로그아웃</title>
<style>body{font-family:-apple-system,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;background:#f6f7f9;color:#1f2328;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px;max-width:400px;width:100%;margin:16px;text-align:center}h1{font-size:18px;margin:0 0 12px}p{line-height:1.6;margin:8px 0;overflow-wrap:anywhere}
.actions{display:flex;gap:8px;margin-top:20px}.actions>*{flex:1 1 0;padding:12px 16px;border-radius:8px;font-size:15px;min-height:44px;font-family:inherit;box-sizing:border-box;text-decoration:none;cursor:pointer}
button{border:none;background:#1a1d21;color:#fff}a.cancel{border:1px solid #d5d8dc;color:#1f2328;background:#fff}.muted{color:#6b7280;font-size:13px}</style></head>
<body><div class="card"><h1>로그아웃할까요?</h1>
<p><strong>${escapeHtml(email)}</strong></p>
<p class="muted">gatehouse 로 로그인한 모든 사내 앱에서 로그아웃됩니다.</p>
<form method="post" action="${escapeHtml(action)}"><div class="actions"><a class="cancel" href="${escapeHtml(back)}">취소</a><button type="submit">로그아웃</button></div></form>
</div></body></html>`;
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

  // GET 은 확인 페이지만. 세션이 없으면 물어볼 것도 없으니 바로 돌려보낸다.
  app.get('/logout', async (req, reply) => {
    const rd = safeRedirect((req.query as { rd?: string }).rd);
    const user = await currentUser(req);
    if (!user) return reply.redirect(rd ?? '/');
    return reply
      .header('Cache-Control', 'no-store')
      .header('X-Frame-Options', 'DENY') // 클릭재킹으로 로그아웃 버튼을 누르게 하지 못하게
      .type('text/html; charset=utf-8')
      .send(logoutPage(user.email, rd));
  });

  app.post('/logout', async (req, reply) => {
    // 세션 쿠키는 SameSite=Lax 라 다른 사이트의 POST 에는 실리지 않는다. 같은 사이트(서브도메인)의 다른 앱이 보내는
    // POST 까지 막으려고 Origin 도 본다. Origin 이 없거나 'null'(Referrer-Policy: no-referrer)이면 통과시킨다.
    const origin = req.headers.origin;
    if (origin && origin !== 'null' && origin !== new URL(baseUrl()).origin) {
      return reply.code(403).send({ error: 'cross-origin logout rejected' });
    }
    const rd = safeRedirect((req.query as { rd?: string }).rd);
    const token = req.cookies[SESSION_COOKIE];
    if (token) {
      const user = await getSessionUser(token);
      await destroySession(token);
      if (user) {
        // OP 세션·grant 도 같이 끊는다. 안 그러면 OIDC 앱은 이 브라우저에 코드를 계속 내준다.
        revokeAccount(String(user.id));
        await logEvent('logout', user.email, { userId: user.id, ...clientInfo(req) });
      }
    }
    return reply
      .clearCookie(SESSION_COOKIE, { ...sessionCookieOptions(), maxAge: undefined })
      .redirect(rd ?? '/');
  });

  app.get('/api/me', async (req, reply) => {
    const user = await currentUser(req);
    if (!user) return reply.code(401).send({ error: 'not signed in' });
    return user;
  });
}
