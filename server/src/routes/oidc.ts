import type { FastifyInstance } from 'fastify';
import { oidc } from '../oidc/provider.js';
import { query } from '../db/pool.js';
import { SESSION_COOKIE, getSessionUser } from '../auth/session.js';
import { clientIp } from '../zt/index.js';
import { deniedPage } from '../zt/zt.js';
import { appDeniedPage } from '../auth/appAccess.js';
import { oidcGate } from '../oidc/gate.js';
import { config } from '../config.js';

const MOUNT = '/oidc';

export function registerOidcRoutes(app: FastifyInstance): void {
  // Hand the whole /oidc subtree to oidc-provider's raw Node handler.
  // Express-style originalUrl/baseUrl let the provider detect the mount path
  // so discovery and redirects carry the /oidc prefix.
  const passthrough = (req: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply) => {
    const raw = req.raw as typeof req.raw & { originalUrl?: string; baseUrl?: string };
    raw.originalUrl = raw.url;
    raw.baseUrl = MOUNT;
    raw.url = raw.url!.slice(MOUNT.length) || '/';
    reply.hijack();
    oidc.callback()(raw, reply.raw);
  };
  app.all(`${MOUNT}/*`, passthrough);
  app.all(MOUNT, passthrough);

  // Interaction endpoint: answer login/consent from the gatehouse session.
  // Users never see a page here — just redirects.
  app.get('/oidc-interaction/:uid', async (req, reply) => {
    const details = await oidc.interactionDetails(req.raw, reply.raw);
    const token = req.cookies[SESSION_COOKIE];
    const user = token ? await getSessionUser(token) : null;

    if (!user) {
      // Sign in with gatehouse first, then come back and resume.
      return reply.redirect(`/login?rd=${encodeURIComponent(`/oidc-interaction/${details.uid}`)}`);
    }

    // 코드를 내주기 전 관문: 앱 접근 정책 + (enforce 대상이면) 기기 판정. login·consent 어느 단계로 들어와도 본다.
    // device grant 클라이언트(CLI·VPN·에이전트)는 기기 판정으로 막지 않고 기록만 한다 — oidcGate 가 가린다.
    const clientId = String(details.params.client_id ?? '');
    const gate = await oidcGate(user, clientId, clientIp(req), { recordMonitor: details.prompt.name === 'login' });
    if (!gate.ok) {
      const html =
        gate.reason === 'app_access'
          ? appDeniedPage({ app: await clientName(clientId), email: user.email })
          : deniedPage({ verdict: gate.zt.verdict, wardUrl: config.zt.wardPublicUrl, hostname: gate.zt.device?.hostname });
      // interaction 은 끝내지 않는다(코드·토큰이 나가지 않는다). 조치 뒤 이 주소를 새로 고치면 다시 판정한다(10분 안).
      return reply
        .code(403)
        .header('X-Auth-Denied', gate.reason === 'app_access' ? 'app_access' : gate.zt.verdict)
        .type('text/html; charset=utf-8')
        .send(html);
    }

    if (details.prompt.name === 'login') {
      return finished(req, reply, { login: { accountId: String(user.id) } });
    }

    if (details.prompt.name === 'consent') {
      // Internal clients only — consent is implicit.
      const grant = new oidc.Grant({
        accountId: String(user.id),
        clientId: String(details.params.client_id),
      });
      const missing = details.prompt.details as {
        missingOIDCScope?: string[];
        missingOIDCClaims?: string[];
      };
      if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
      if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
      const grantId = await grant.save();
      return finished(req, reply, { consent: { grantId } });
    }

    return reply.code(400).send({ error: `unsupported prompt: ${details.prompt.name}` });
  });

  /** 거부 안내에 보여 줄 앱 이름. */
  async function clientName(clientId: string): Promise<string> {
    const { rows } = await query<{ name: string }>('SELECT name FROM oidc_clients WHERE client_id = $1', [clientId]);
    return rows[0]?.name ? `${rows[0].name} (${clientId})` : clientId;
  }

  async function finished(
    req: import('fastify').FastifyRequest,
    reply: import('fastify').FastifyReply,
    result: Record<string, unknown>,
  ) {
    reply.hijack();
    await oidc.interactionFinished(req.raw, reply.raw, result, {
      mergeWithLastSubmission: true,
    });
  }
}
