import type { FastifyInstance } from 'fastify';
import { oidc } from '../oidc/provider.js';
import { SESSION_COOKIE, getSessionUser } from '../auth/session.js';

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
