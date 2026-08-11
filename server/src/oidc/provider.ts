import Provider from 'oidc-provider';
import { generateKeyPair, exportJWK } from 'jose';
import { randomBytes } from 'node:crypto';
import { query } from '../db/pool.js';
import { config, baseUrl } from '../config.js';
import { GatehouseAdapter } from './adapter.js';

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
    // Put email/name claims in the id_token too, not only userinfo — some
    // integrations (ALB, simple middlewares) never call userinfo.
    conformIdTokenClaims: false,
    features: {
      devInteractions: { enabled: false },
      // Device flow for browserless/native clients (opentunnel VPN):
      // client shows a code, the user approves it at /oidc/device in a browser.
      deviceFlow: {
        enabled: true,
        userCodeInputSource: async (ctx, form) => {
          ctx.type = 'html';
          // oidc-provider's form carries no submit button; without one there is
          // no visible way to continue on a phone.
          ctx.body = devicePage(
            '기기 로그인',
            `<p>기기에 표시된 코드를 입력하세요.</p>${form}
             <div class="actions"><button type="submit" form="op.deviceInputForm">계속</button></div>`,
          );
        },
        userCodeConfirmSource: async (ctx, form, client, _deviceInfo, userCode) => {
          ctx.type = 'html';
          const name = (client as { clientName?: string }).clientName ?? client.clientId;
          // Always add submit buttons to the form (oidc-provider's form lacks them).
          // Styling lives in devicePage()'s stylesheet so the buttons stack on phones.
          const buttons = `<div class="actions">
<input type="submit" value="승인">
<input type="submit" name="deny" class="deny" value="거절">
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
            `<p><strong>${escapeHtml(name)}</strong> 기기의 로그인을 승인할까요?</p>
             <p class="code">${escapeHtml(userCode)}</p>${formWithButtons}
             <p class="muted">본인이 시작한 로그인이 아니라면 이 창을 닫으세요.</p>`,
          );
        },
        successSource: async (ctx) => {
          ctx.type = 'html';
          ctx.body = devicePage('완료', '<p>기기 로그인이 승인되었습니다. 이 창을 닫고 기기로 돌아가세요.</p>');
        },
      },
    },
    interactions: {
      // Handled by gatehouse itself outside the /oidc mount; the existing
      // session cookie answers login+consent without showing the user anything.
      url: (_ctx, interaction) => `/oidc-interaction/${interaction.uid}`,
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
      Session: 14 * 24 * 3600,
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
