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
import { registerInternalRoutes } from './routes/internal.js';
import { initOidc } from './oidc/provider.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main(): Promise<void> {
  await migrate();
  await initGoogle();

  const app = Fastify({
    logger: { level: process.env.LOG_LEVEL ?? 'info' },
    trustProxy: 1, // nginx 한 홉만 믿는다. true 면 클라이언트가 보낸 X-Forwarded-For 첫 항목이 req.ip 가 돼 제로트러스트 기기 IP 를 사칭할 수 있다
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
  registerInternalRoutes(app, config.internalSecret);

  app.get('/healthz', async () => ({ ok: true }));

  // Serve the built console when present (production image / `npm run build`).
  const webDist = path.resolve(__dirname, '../../web/dist');
  if (existsSync(webDist)) {
    await app.register(fastifyStatic, { root: webDist });
    app.setNotFoundHandler((req, reply) => {
      // SPA fallback for non-API GET routes.
      if (
        req.method === 'GET' &&
        !req.url.startsWith('/api/') &&
        !req.url.startsWith('/auth/') &&
        !req.url.startsWith('/internal/') // 시크릿이 없어 꺼진 /internal/account 가 SPA(200)로 답하지 않게
      ) {
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
