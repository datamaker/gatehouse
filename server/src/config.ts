function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}

const publicUrl = (process.env.GATEHOUSE_PUBLIC_URL ?? '').replace(/\/$/, '');
const list = (v: string | undefined): string[] =>
  (v ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
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
  /**
   * 제로트러스트(ward 디바이스 상태 판정). off 면 아무것도 하지 않는다.
   * monitor 는 기록만, enforce 는 compliant 기기에서만 forward-auth 를 통과시킨다.
   */
  zt: {
    mode: (['off', 'monitor', 'enforce'] as const).find((m) => m === (process.env.GATEHOUSE_ZT_MODE ?? 'off')) ?? 'off',
    wardUrl: (process.env.GATEHOUSE_WARD_URL ?? 'http://ward:9600').replace(/\/$/, ''),
    wardSecret: process.env.GATEHOUSE_WARD_SECRET ?? '',
    /** ward 가 안 닿을 때 통과(true, 기본) / 차단(false). */
    failOpen: (process.env.GATEHOUSE_ZT_FAIL_OPEN ?? 'true') !== 'false',
    cacheSec: parseInt(process.env.GATEHOUSE_ZT_CACHE_SEC ?? '60', 10),
    timeoutMs: parseInt(process.env.GATEHOUSE_ZT_TIMEOUT_MS ?? '1000', 10),
    exemptEmails: list(process.env.GATEHOUSE_ZT_EXEMPT_EMAILS),
    exemptHosts: list(process.env.GATEHOUSE_ZT_EXEMPT_HOSTS),
    /** 사용자에게 보여 줄 ward 콘솔 주소. */
    wardPublicUrl: process.env.GATEHOUSE_WARD_PUBLIC_URL ?? 'https://ward.datasee.co.kr',
  },
};

if (config.zt.mode !== 'off' && !config.zt.wardSecret) {
  console.warn(`GATEHOUSE_ZT_MODE=${config.zt.mode} 인데 GATEHOUSE_WARD_SECRET 이 없습니다. ward 조회는 전부 실패(fail-${config.zt.failOpen ? 'open' : 'closed'})합니다`);
}

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
