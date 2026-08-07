function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}

const publicUrl = (process.env.GATEHOUSE_PUBLIC_URL ?? '').replace(/\/$/, '');
const port = parseInt(process.env.PORT ?? '9100', 10);

export const config = {
  port,
  host: process.env.HOST ?? '0.0.0.0',
  databaseUrl:
    process.env.DATABASE_URL ??
    'postgres://gatehouse:gatehouse@localhost:5435/gatehouse',
  /** Public base URL of gatehouse itself, e.g. https://auth.datasee.co.kr */
  publicUrl,
  googleClientId: required('GOOGLE_CLIENT_ID'),
  googleClientSecret: required('GOOGLE_CLIENT_SECRET'),
  /** Google Workspace hosted domains allowed to sign in (`hd` claim). */
  allowedDomains: (process.env.GATEHOUSE_ALLOWED_DOMAINS ?? 'datasee.co.kr')
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean),
  /**
   * Domain the session cookie is scoped to, e.g. `datasee.co.kr` so every
   * subdomain behind forward-auth shares the login. Empty = host-only (dev).
   */
  cookieDomain: process.env.GATEHOUSE_COOKIE_DOMAIN ?? '',
  /** Secret for signing the short-lived OAuth state cookie. */
  cookieSecret: process.env.GATEHOUSE_COOKIE_SECRET ?? '',
  sessionTtlHours: parseInt(process.env.GATEHOUSE_SESSION_TTL_HOURS ?? '12', 10),
  /** Emails that are granted admin on sign-in (bootstrap; admins can promote others in the console). */
  adminEmails: (process.env.GATEHOUSE_ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean),
  /**
   * Domains that `?rd=` post-login redirects may point at (registrable
   * domains; subdomains included). Defaults to cookieDomain + allowedDomains.
   */
  redirectDomains: (process.env.GATEHOUSE_REDIRECT_DOMAINS ?? '')
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean),
};

if (config.redirectDomains.length === 0) {
  config.redirectDomains = [
    ...new Set([config.cookieDomain, ...config.allowedDomains].filter(Boolean)),
  ];
}

export function baseUrl(): string {
  return config.publicUrl || `http://localhost:${config.port}`;
}

/** True when gatehouse is served over https (controls Secure cookies). */
export const isSecure = baseUrl().startsWith('https://');

if (!config.cookieSecret) {
  if (isSecure) throw new Error('GATEHOUSE_COOKIE_SECRET is required in production');
  console.warn('GATEHOUSE_COOKIE_SECRET not set; using insecure dev secret');
  config.cookieSecret = 'gatehouse-dev-secret-do-not-use-in-prod';
}
