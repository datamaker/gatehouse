import Provider, { interactionPolicy } from 'oidc-provider';
import { generateKeyPair, exportJWK } from 'jose';
import { randomBytes } from 'node:crypto';
import { query } from '../db/pool.js';
import { config, baseUrl } from '../config.js';
import { GatehouseAdapter } from './adapter.js';
import { oidcGate } from './gate.js';
import { SESSION_COOKIE, getSessionUser } from '../auth/session.js';
import { rawClientIp } from '../zt/index.js';

export let oidc: Provider;

/** Signing key lives in Postgres so issued tokens survive restarts. */
async function loadOrCreateJwk(): Promise<Record<string, unknown>> {
  const { rows } = await query<{ jwk: Record<string, unknown> }>(
    'SELECT jwk FROM oidc_jwks ORDER BY id DESC LIMIT 1',
  );
  if (rows[0]) return rows[0].jwk;

  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = (await exportJWK(privateKey)) as Record<string, unknown>;
  jwk.kid = randomBytes(8).toString('hex');
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  await query('INSERT INTO oidc_jwks (jwk) VALUES ($1)', [JSON.stringify(jwk)]);
  return jwk;
}

/**
 * OP 세션 재사용 조건. oidc-provider 는 자기 세션 쿠키만 있으면 interaction 없이 코드를 내주는데,
 * 그러면 gatehouse 에서 로그아웃·세션 종료·비활성화된 브라우저도 계속 통과한다.
 * 그래서 authorization·device 요청마다 "이 브라우저의 gatehouse 세션이 살아 있고 OP 세션과 같은 계정인지",
 * 그리고 앱 접근 정책·기기 판정(enforce 대상)을 다시 본다. 아니면 login 프롬프트를 요구해
 * /oidc-interaction → gatehouse 로그인(또는 거부 안내)으로 보낸다.
 */
function buildInteractionPolicy() {
  const policy = interactionPolicy.base();
  const { Check } = interactionPolicy;
  policy.get('login')!.checks.add(
    new Check('gatehouse_session', 'gatehouse 세션 확인이 필요합니다', async (ctx) => {
      const accountId = ctx.oidc.session?.accountId;
      if (!accountId) return Check.NO_NEED_TO_PROMPT; // 기본 no_session 검사가 처리한다
      // 방금 /oidc-interaction 을 통과해 돌아온 요청은 거기서 같은 관문을 이미 지났다(다시 요구하면 무한 왕복).
      if (ctx.oidc.result?.login) return Check.NO_NEED_TO_PROMPT;
      const token = ctx.cookies.get(SESSION_COOKIE);
      const user = token ? await getSessionUser(token) : null;
      if (!user || String(user.id) !== accountId) return Check.REQUEST_PROMPT;
      const clientId = ctx.oidc.client?.clientId ?? String(ctx.oidc.params?.client_id ?? '');
      const gate = await oidcGate(user, clientId, rawClientIp(ctx.req), { recordMonitor: false });
      return gate.ok ? Check.NO_NEED_TO_PROMPT : Check.REQUEST_PROMPT;
    }),
  );
  return policy;
}

/** 기기 승인 화면에 보여 줄 요청 시각(KST). */
function formatKst(ms: number): string {
  return new Date(ms).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', dateStyle: 'medium', timeStyle: 'medium' });
}

export async function initOidc(): Promise<Provider> {
  const jwk = await loadOrCreateJwk();

  oidc = new Provider(`${baseUrl()}/oidc`, {
    adapter: GatehouseAdapter,
    jwks: { keys: [jwk as never] },
    cookies: { keys: [config.cookieSecret] },
    scopes: ['openid', 'email', 'profile'],
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name', 'picture'],
    },
    pkce: { required: () => true },
    // oidc-provider refuses any request carrying an Origin header unless this
    // says otherwise. Browser-based public clients (the vault Chrome extension,
    // a chrome-extension:// origin) call the token endpoint directly, so allow
    // exactly that pairing. Confidential clients exchange server-side and never
    // send an Origin; nothing else is opened up.
    clientBasedCORS: (_ctx, origin, client) =>
      client.tokenEndpointAuthMethod === 'none' && origin.startsWith('chrome-extension://'),
    // Put email/name claims in the id_token too, not only userinfo — some
    // integrations (ALB, simple middlewares) never call userinfo.
    conformIdTokenClaims: false,
    features: {
      devInteractions: { enabled: false },
      // Device flow for browserless/native clients (opentunnel VPN):
      // client shows a code, the user approves it at /oidc/device in a browser.
      deviceFlow: {
        enabled: true,
        // 기기(CLI·VPN 앱)가 코드를 요청한 순간의 정보. 승인 화면에서 "내가 시작한 요청이 맞나" 를 판단할 근거로 보여 준다.
        // IP 는 nginx 가 쓴 X-Forwarded-For 마지막 항목만 믿는다(기본 구현의 ctx.ip 는 첫 항목이라 사칭 가능).
        deviceInfo: (ctx) => ({
          ip: rawClientIp(ctx.req),
          ua: ctx.get('user-agent'),
          at: Date.now(),
        }),
        userCodeInputSource: async (ctx, form, _out, err) => {
          ctx.type = 'html';
          // 거절·만료·오타 뒤에도 이 화면이 다시 그려진다. 무슨 일이 있었는지 알려 준다.
          const notice: Record<string, string> = {
            AbortedError: '로그인 요청을 거절했습니다. 기기에서는 로그인이 취소됩니다.',
            NotFoundError: '코드를 찾을 수 없습니다. 기기에 표시된 코드를 다시 확인하세요.',
            ExpiredError: '코드가 만료되었습니다. 기기에서 로그인을 다시 시작하세요.',
            AlreadyUsedError: '이미 사용된 코드입니다. 기기에서 로그인을 다시 시작하세요.',
            NoCodeError: '코드를 입력하세요.',
          };
          const msg = err ? (notice[err.name] ?? '요청을 처리하지 못했습니다. 다시 시도하세요.') : '';
          // oidc-provider's form carries no submit button; without one there is
          // no visible way to continue on a phone.
          ctx.body = devicePage(
            '기기 로그인',
            `${msg ? `<p class="warn">${escapeHtml(msg)}</p>` : ''}<p>기기에 표시된 코드를 입력하세요.</p>${form}
             <div class="actions"><button type="submit" form="op.deviceInputForm">계속</button></div>`,
          );
        },
        // `/oidc/device?user_code=…`(verification_uri_complete) 로 열어도 oidc-provider 는 코드를 채워 이 화면까지만 넘긴다.
        // 승인은 confirm=yes 가 실린 이 화면의 POST 로만 일어난다 — 그래서 여기서 요청 정보를 보여 주고 직접 누르게 한다.
        userCodeConfirmSource: async (ctx, form, client, deviceInfo, userCode) => {
          ctx.type = 'html';
          const name = (client as { clientName?: string }).clientName ?? client.clientId;
          const info = (deviceInfo ?? {}) as { ip?: unknown; ua?: unknown; at?: unknown };
          const ip = typeof info.ip === 'string' && info.ip ? info.ip : '알 수 없음';
          const ua = typeof info.ua === 'string' && info.ua ? info.ua.slice(0, 200) : '알 수 없음';
          const at = typeof info.at === 'number' ? formatKst(info.at) : '알 수 없음';
          // Always add submit buttons to the form (oidc-provider's form lacks them).
          // Styling lives in devicePage()'s stylesheet so the buttons stack on phones.
          const buttons = `<div class="actions">
<input type="submit" value="승인">
<input type="submit" name="abort" class="deny" value="거절">
</div>`;
          const formWithButtons = form
            ? form.replace('</form>', `${buttons}</form>`)
            : `<form method="post">
<input type="hidden" name="user_code" value="${escapeHtml(userCode)}">
<input type="hidden" name="confirm" value="yes">
${buttons}
</form>`;
          ctx.body = devicePage(
            '기기 승인',
            `<p><strong>${escapeHtml(name)}</strong> 의 로그인을 승인할까요?</p>
             <p class="code">${escapeHtml(userCode)}</p>
             <dl class="req">
               <dt>요청한 앱</dt><dd>${escapeHtml(name)} <span class="muted">(${escapeHtml(client.clientId)})</span></dd>
               <dt>요청 IP</dt><dd>${escapeHtml(ip)}</dd>
               <dt>요청 기기</dt><dd>${escapeHtml(ua)}</dd>
               <dt>요청 시각</dt><dd>${escapeHtml(at)}</dd>
             </dl>
             <p class="warn">본인이 방금 시작한 로그인이 아니면 승인하지 마세요.</p>
             ${formWithButtons}
             <p class="muted">코드가 기기 화면에 보이는 것과 같은지, 요청 정보가 내 기기와 맞는지 확인한 뒤 승인하세요.</p>`,
          );
        },
        successSource: async (ctx) => {
          ctx.type = 'html';
          // Count down, then try hard to close the tab. Browsers only close a
          // window a script can claim: a tab opened via `open <url>` has a
          // single-entry history and often closes, but a hand-opened tab or one
          // with back-history won't. Try window.close(), then the
          // open-self-then-close trick, and finally fall back to an instruction.
          ctx.body = devicePage(
            '완료',
            `<p>기기 로그인이 승인되었습니다.</p>
             <p class="muted" id="closeMsg">이 창은 <span id="count">3</span>초 후 자동으로 닫힙니다.</p>
             <script>
               (function () {
                 var n = 3;
                 var el = document.getElementById('count');
                 var msg = document.getElementById('closeMsg');
                 var t = setInterval(function () {
                   n -= 1;
                   if (n > 0) { el.textContent = n; return; }
                   clearInterval(t);
                   try { window.close(); } catch (e) {}
                   // Re-claim this window as script-opened, then close — lets some
                   // browsers close a tab the plain window.close() wouldn't.
                   try { window.open('', '_self'); window.close(); } catch (e) {}
                   // Still here a moment later means the browser blocked it.
                   setTimeout(function () {
                     msg.textContent = '이제 이 창을 닫고 기기로 돌아가세요.';
                   }, 400);
                 }, 1000);
               })();
             </script>`,
          );
        },
      },
    },
    interactions: {
      // Handled by gatehouse itself outside the /oidc mount; the existing
      // session cookie answers login+consent without showing the user anything.
      url: (_ctx, interaction) => `/oidc-interaction/${interaction.uid}`,
      policy: buildInteractionPolicy(),
    },
    async findAccount(_ctx, sub) {
      const { rows } = await query<{
        id: number;
        email: string;
        name: string;
        picture: string | null;
      }>('SELECT id, email, name, picture FROM users WHERE id = $1 AND is_active', [Number(sub)]);
      const user = rows[0];
      if (!user) return undefined;
      return {
        accountId: sub,
        claims: async () => ({
          sub,
          email: user.email,
          email_verified: true,
          name: user.name,
          picture: user.picture ?? undefined,
        }),
      };
    },
    ttl: {
      AuthorizationCode: 60,
      AccessToken: 3600,
      IdToken: 3600,
      Grant: 14 * 24 * 3600,
      // OP 세션은 gatehouse 유휴 만료보다 길면 안 된다(길면 gatehouse 세션이 끝난 뒤에도 코드가 나간다).
      Session: Math.max(60, Math.min(14 * 24 * 3600, config.sessionIdleHours * 3600)),
      Interaction: 600,
    },
    renderError: async (ctx, out, _err) => {
      ctx.type = 'json';
      ctx.body = out;
    },
  });

  // TLS terminates at nginx; trust X-Forwarded-Proto.
  oidc.proxy = true;
  return oidc;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function devicePage(title: string, body: string): string {
  return `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>gatehouse — ${escapeHtml(title)}</title>
<style>
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body { font-family: system-ui, -apple-system, 'Apple SD Gothic Neo', sans-serif; background: #f6f7f9;
         display: grid; place-items: center; min-height: 100vh; margin: 0; color: #1a1d21;
         padding: 24px max(16px, env(safe-area-inset-left)) calc(24px + env(safe-area-inset-bottom))
                  max(16px, env(safe-area-inset-right)); }
  .card { background: #fff; border: 1px solid #e4e6ea; border-radius: 12px; padding: 32px 40px;
          width: 100%; max-width: 400px; text-align: center; }
  h1 { font-size: 18px; margin: 0 0 12px; }
  p { overflow-wrap: anywhere; }
  .code { font-size: 24px; letter-spacing: 3px; font-weight: 700; background: #f4f5f7;
          border-radius: 8px; padding: 10px; }
  .muted { color: #888; font-size: 13px; }
  .req { text-align: left; font-size: 13px; background: #f4f5f7; border-radius: 8px; padding: 12px 14px;
         margin: 12px 0; display: grid; grid-template-columns: auto 1fr; gap: 6px 12px; }
  .req dt { color: #666; white-space: nowrap; }
  .req dd { margin: 0; overflow-wrap: anywhere; }
  .warn { color: #991b1b; background: #fee2e2; border-radius: 8px; padding: 10px 12px; font-weight: 600;
          font-size: 14px; }
  /* 16px+ keeps iOS Safari from zooming the page when the field takes focus. */
  input[type=text] { width: 100%; padding: 12px; font-size: 18px; text-align: center;
          letter-spacing: 2px; border: 1px solid #d5d8dc; border-radius: 8px; margin: 12px 0;
          min-height: 48px; }
  button, input[type=submit] { padding: 12px 24px; font-size: 15px; border-radius: 8px; border: none;
          background: #1a1d21; color: #fff; cursor: pointer; min-height: 44px; font-family: inherit; }
  input[type=submit].deny { background: #888; }
  .actions { display: flex; justify-content: center; gap: 8px; margin-top: 16px; }
  .actions > * { flex: 1 1 0; }
  @media (max-width: 480px) {
    .card { padding: 24px 20px; }
    /* Stack the approve/deny pair so neither is a cramped, mis-tappable target. */
    .actions { flex-direction: column; }
  }
</style>
<body><div class="card"><h1>${escapeHtml(title)}</h1>${body}</div></body>`;
}
