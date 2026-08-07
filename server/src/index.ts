import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { config } from './config.js';
import { migrate } from './db/migrate.js';
import { initGoogle } from './auth/google.js';
import { startSessionCleanup } from './auth/session.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerVerifyRoutes } from './routes/verify.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerOidcRoutes } from './routes/oidc.js';
import { initOidc } from './oidc/provider.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main(): Promise<void> {
  await migrate();
  await initGoogle();

  const app = Fastify({
    logger: { level: process.env.LOG_LEVEL ?? 'info' },
    trustProxy: true,
  });

  await app.register(cookie, { secret: config.cookieSecret });

  // HTML form posts (e.g. the console's logout button). Bodies are ignored —
  // except under /oidc, where the stream must stay untouched so oidc-provider
  // can parse token/revocation requests itself.
  app.addContentTypeParser('application/x-www-form-urlencoded', (req, payload, done) => {
    if (req.url.startsWith('/oidc')) return done(null, undefined);
    payload.on('data', () => {});
    payload.on('end', () => done(null, {}));
    payload.on('error', done);
  });

  await initOidc();

  registerAuthRoutes(app);
  registerVerifyRoutes(app);
  registerAdminRoutes(app);
  registerOidcRoutes(app);

  app.get('/healthz', async () => ({ ok: true }));

  // Serve the built console when present (production image / `npm run build`).
  const webDist = path.resolve(__dirname, '../../web/dist');
  if (existsSync(webDist)) {
    await app.register(fastifyStatic, { root: webDist });
    app.setNotFoundHandler((req, reply) => {
      // SPA fallback for non-API GET routes.
      if (req.method === 'GET' && !req.url.startsWith('/api/') && !req.url.startsWith('/auth/')) {
        return reply.sendFile('index.html');
      }
      return reply.code(404).send({ error: 'not found' });
    });
  }

  startSessionCleanup();

  await app.listen({ port: config.port, host: config.host });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
