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
  /**
   * 세션 수명(sliding). 유휴: 마지막 활동 뒤 이 시간 안에 요청이 없으면 끝.
   * 절대 상한: 로그인 뒤 이 시간이 지나면 활동과 무관하게 끝. 연장은
   * touch 간격마다 한 번만 DB 에 쓴다(forward-auth 는 요청마다 불린다).
   */
  sessionIdleHours: parseInt(
    process.env.GATEHOUSE_SESSION_IDLE_HOURS ?? process.env.GATEHOUSE_SESSION_TTL_HOURS ?? '24',
    10,
  ),
  sessionMaxHours: parseInt(process.env.GATEHOUSE_SESSION_MAX_HOURS ?? '168', 10),
  sessionTouchMinutes: parseInt(process.env.GATEHOUSE_SESSION_TOUCH_MINUTES ?? '10', 10),
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
   * 계정 상태 조회(`GET /internal/account`)용 공유 시크릿. 비어 있으면 라우트 자체를 등록하지 않는다(404).
   * 자체 세션·토큰을 가진 앱이 이 값으로 비활성화·세션 종료를 1분 안에 따라온다.
   */
  internalSecret: process.env.GATEHOUSE_INTERNAL_SECRET ?? '',
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
    /** 전역 모드가 monitor 여도 이 사용자들에게는 enforce 를 적용한다(전역 off 면 아무 효과 없음). */
    enforceEmails: list(process.env.GATEHOUSE_ZT_ENFORCE_EMAILS),
    /** OIDC 로그인 단계에서 기기 판정으로 막지 않을 client_id (device grant 클라이언트는 자동으로 제외된다). */
    oidcExemptClients: list(process.env.GATEHOUSE_ZT_OIDC_EXEMPT_CLIENTS),
    /** 사용자에게 보여 줄 ward 콘솔 주소. */
    wardPublicUrl: process.env.GATEHOUSE_WARD_PUBLIC_URL ?? 'https://ward.datasee.co.kr',
  },
};

if (config.zt.mode !== 'off' && !config.zt.wardSecret) {
  console.warn(`GATEHOUSE_ZT_MODE=${config.zt.mode} 인데 GATEHOUSE_WARD_SECRET 이 없습니다. ward 조회는 전부 실패(fail-${config.zt.failOpen ? 'open' : 'closed'})합니다`);
}

if (process.env.GATEHOUSE_SESSION_TTL_HOURS && !process.env.GATEHOUSE_SESSION_IDLE_HOURS) {
  console.warn('GATEHOUSE_SESSION_TTL_HOURS 는 더 이상 쓰지 않습니다. GATEHOUSE_SESSION_IDLE_HOURS(유휴) / GATEHOUSE_SESSION_MAX_HOURS(절대 상한) 로 바꾸세요. 지금은 유휴 시간으로 해석합니다');
}
if (config.sessionMaxHours < config.sessionIdleHours) {
  console.warn(`GATEHOUSE_SESSION_MAX_HOURS(${config.sessionMaxHours}) < IDLE(${config.sessionIdleHours}) — 상한을 유휴 시간으로 맞춥니다`);
  config.sessionMaxHours = config.sessionIdleHours;
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
