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
