/**
 * 제로트러스트 1차: ward(엔드포인트 보안)의 디바이스 상태로 접속을 판정한다.
 *
 * 이 모듈은 설정(config.ts)과 DB 를 모르게 만들어 두었다 — 옵션과 기록 함수를 밖에서 주입한다.
 * 그래야 GOOGLE_CLIENT_ID 없이도, Postgres 없이도 가짜 ward 서버만으로 테스트할 수 있다.
 *
 * 브라우저↔기기 바인딩은 ward 에이전트가 보고한 last_ip 와 요청 IP 의 일치로 한다(사무실·VPN 전제).
 * NAT 뒤에서 여러 사람이 같은 IP 를 쓰면 다른 사람의 기기와 맞을 수 있다 — 그래서 ward 는 "그 사용자의"
 * 기기 중에서만 IP 를 맞춘다(email 로 먼저 좁힌다).
 */

export type ZtMode = 'off' | 'monitor' | 'enforce';
export type ZtVerdict = 'compliant' | 'noncompliant' | 'unknown' | 'no_device';

export interface ZtDevice {
  id: string;
  hostname: string;
  platform: string;
  posture_status: 'compliant' | 'noncompliant' | 'unknown';
  last_seen_at: string;
  last_ip: string | null;
  ip_match: boolean;
  online: boolean;
}

export interface WardPosture {
  devices: ZtDevice[];
  verdict: ZtVerdict;
  /** ward 가 verdict 에 덧붙인 기계용 사유(지금은 'agent_offline' 하나). 형식이 맞지 않으면 버린다. */
  reason?: string;
}

/** ward 가 준 기계용 사유. 헤더·쿼리·DB 로 그대로 흘러가므로 소문자와 밑줄만, 40자까지만 받는다. */
const REASON_RE = /^[a-z_]{1,40}$/;
export function parseReason(v: unknown): string | undefined {
  return typeof v === 'string' && REASON_RE.test(v) ? v : undefined;
}

export interface ZtOptions {
  mode: ZtMode;
  wardUrl: string;
  wardSecret: string;
  /** ward 가 안 닿거나 1초를 넘기면 통과시킬지(true) 막을지(false). */
  failOpen: boolean;
  cacheSec: number;
  timeoutMs: number;
  exemptEmails: string[];
  exemptHosts: string[];
  /**
   * "막지 않고 제한"할 앱 호스트(면제 호스트와 같은 매칭 규칙). enforce 에서 거부될 판정이어도 통과시키되 restricted 로 표시한다.
   * 면제가 아니다 — 판정은 그대로 하고 기록한다. ward 콘솔처럼 미준수 사용자가 "무엇을 고쳐야 하는지" 봐야 하는 앱용.
   */
  softHosts?: string[];
  /** 전역 모드가 monitor 일 때도 enforce 를 적용할 사용자(소문자 이메일). 전역이 off 면 무시된다. */
  enforceEmails?: string[];
}

export interface ZtResult {
  /** 판정에 쓴 "실효" 모드(사용자별 enforce 반영). off 면 아무것도 안 한 것. */
  mode: ZtMode;
  /** ward 가 준 verdict. 조회 실패면 'error', 면제면 'exempt'. */
  verdict: ZtVerdict | 'error' | 'exempt';
  /** 통과 여부. monitor 는 항상 true. */
  allowed: boolean;
  /** 소프트 호스트라서 통과시켰지만 원래는 거부될 판정이었다(enforce 일 때만 true). 앱이 이 세션의 권한을 줄인다. */
  restricted: boolean;
  /** ward 의 기계용 사유(예: 'agent_offline'). 없으면 필드 자체가 없다. */
  reason?: string;
  device: ZtDevice | null;
  /** ward 조회 캐시에서 꺼낸 결과인지. 기록은 fresh 거나 그 앱(host)의 첫 접속일 때 남는다(요청마다 쌓이지 않게). */
  cached: boolean;
  error?: string;
}

export interface ZtCheckInput {
  email: string;
  /** forward-auth 가 보호하는 앱 호스트(X-Forwarded-Host) 또는 OIDC client_id. */
  host: string;
  ip: string;
  /** true 면 이 판정은 기록만 한다(실효 모드를 monitor 로 낮춘다). device grant OIDC 클라이언트처럼 IP 바인딩이 다른 경로용. */
  monitorOnly?: boolean;
}

/** ward 에서 사용자의 디바이스 상태를 가져온다. 예외는 던지지 않고 null 을 준다. */
export async function fetchPosture(
  opts: Pick<ZtOptions, 'wardUrl' | 'wardSecret' | 'timeoutMs'>,
  email: string,
  ip: string,
): Promise<{ ok: true; posture: WardPosture } | { ok: false; error: string }> {
  const url = new URL('/api/zt/posture', opts.wardUrl);
  url.searchParams.set('email', email);
  url.searchParams.set('ip', ip);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs);
  try {
    const res = await fetch(url, { headers: { 'x-ward-secret': opts.wardSecret }, signal: ctl.signal });
    if (res.status === 404) {
      // ward 가 모르는 사용자 = 등록된 기기가 없다.
      return { ok: true, posture: { devices: [], verdict: 'no_device' } };
    }
    if (!res.ok) return { ok: false, error: `ward HTTP ${res.status}` };
    const body = (await res.json()) as Partial<Omit<WardPosture, 'reason'>> & { reason?: unknown };
    const verdict = body.verdict;
    if (!verdict || !['compliant', 'noncompliant', 'unknown', 'no_device'].includes(verdict)) {
      return { ok: false, error: 'ward 응답에 verdict 가 없습니다' };
    }
    const reason = parseReason(body.reason);
    return {
      ok: true,
      posture: { devices: Array.isArray(body.devices) ? body.devices : [], verdict, ...(reason ? { reason } : {}) },
    };
  } catch (err) {
    const e = err as Error;
    return { ok: false, error: e.name === 'AbortError' ? `ward timeout (${opts.timeoutMs}ms)` : e.message };
  } finally {
    clearTimeout(timer);
  }
}

/** ip_match 인 기기 중 가장 최근 것. ward 의 verdict 와 같은 기준이다. */
export function pickDevice(devices: ZtDevice[]): ZtDevice | null {
  const matched = devices.filter((d) => d.ip_match);
  if (matched.length === 0) return null;
  return matched.sort((a, b) => (a.last_seen_at < b.last_seen_at ? 1 : -1))[0];
}

/** 순수 판정: 모드·verdict·fail-open 으로 통과 여부를 정한다. */
export function decide(mode: ZtMode, verdict: ZtResult['verdict'], failOpen: boolean): boolean {
  if (mode !== 'enforce') return true;
  if (verdict === 'exempt') return true;
  if (verdict === 'error') return failOpen;
  return verdict === 'compliant';
}

/**
 * 소프트 호스트까지 반영한 판정. 소프트 호스트는 decide 가 거부할 때(= enforce 에서만 생긴다) 통과로 바꾸고 restricted 를 세운다.
 * monitor·준수·면제처럼 원래 통과인 경우는 restricted=false.
 */
export function decideAccess(
  mode: ZtMode,
  verdict: ZtResult['verdict'],
  failOpen: boolean,
  softHost: boolean,
): { allowed: boolean; restricted: boolean } {
  const allowed = decide(mode, verdict, failOpen);
  if (!allowed && softHost) return { allowed: true, restricted: true };
  return { allowed, restricted: false };
}

/**
 * 사용자별 실효 모드. 전역 off 는 무엇으로도 켜지지 않고, 전역 enforce 는 전원 enforce,
 * 전역 monitor 는 enforce 목록에 있는 사용자만 enforce.
 */
export function effectiveMode(globalMode: ZtMode, enforceEmails: readonly string[], email: string): ZtMode {
  if (globalMode !== 'monitor') return globalMode;
  return enforceEmails.includes(email.trim().toLowerCase()) ? 'enforce' : 'monitor';
}

function matchHost(host: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) return host === pattern.slice(2) || host.endsWith(pattern.slice(1));
  return host === pattern;
}

export class ZeroTrust {
  /** ward 조회 결과만 캐시한다. 모드·통과 여부는 호출마다 실효 모드로 다시 계산한다(같은 사용자도 경로에 따라 모드가 다를 수 있다). */
  private cache = new Map<string, { at: number; verdict: ZtVerdict | 'error'; device: ZtDevice | null; reason?: string; error?: string }>();
  /** email|ip|host → 마지막 기록 시각. */
  private recorded = new Map<string, number>();
  private enforceList: string[];

  constructor(
    private opts: ZtOptions,
    /** fresh 판정마다, 그리고 캐시를 탔어도 그 앱(host)의 TTL 안 첫 접속이면 호출된다(기록용). 실패해도 판정에는 영향이 없어야 한다. */
    private record: (input: ZtCheckInput, result: ZtResult) => Promise<void> | void = () => {},
  ) {
    this.enforceList = (opts.enforceEmails ?? []).map((e) => e.trim().toLowerCase()).filter(Boolean);
  }

  /** 전역 모드. */
  get mode(): ZtMode {
    return this.opts.mode;
  }

  /** 사용자별 enforce 목록(소문자). */
  get enforceEmails(): readonly string[] {
    return this.enforceList;
  }

  /** 이 사용자에게 실제로 적용되는 모드. monitorOnly 면 enforce 를 monitor 로 낮춘다. */
  effectiveMode(email: string, monitorOnly = false): ZtMode {
    const mode = effectiveMode(this.opts.mode, this.enforceList, email);
    return monitorOnly && mode === 'enforce' ? 'monitor' : mode;
  }

  isExempt(email: string, host: string): boolean {
    const e = email.toLowerCase();
    if (this.opts.exemptEmails.includes(e)) return true;
    const h = host.toLowerCase();
    return this.opts.exemptHosts.some((p) => matchHost(h, p));
  }

  /** 소프트 호스트("막지 않고 제한")인지. 면제 여부와는 따로 본다 — 면제가 먼저다. */
  isSoftHost(host: string): boolean {
    const h = host.toLowerCase();
    return (this.opts.softHosts ?? []).some((p) => matchHost(h, p));
  }

  async check(input: ZtCheckInput): Promise<ZtResult> {
    const mode = this.effectiveMode(input.email, input.monitorOnly);
    if (mode === 'off') return { mode, verdict: 'exempt', allowed: true, restricted: false, device: null, cached: false };
    if (this.isExempt(input.email, input.host)) {
      return { mode, verdict: 'exempt', allowed: true, restricted: false, device: null, cached: false };
    }

    const email = input.email.toLowerCase();
    const key = `${email}|${input.ip}`;
    const now = Date.now();
    let hit = this.cache.get(key);
    let fresh = false;
    if (!hit || now - hit.at >= this.opts.cacheSec * 1000) {
      fresh = true;
      const fetched = await fetchPosture(this.opts, input.email, input.ip);
      hit = fetched.ok
        ? { at: now, verdict: fetched.posture.verdict, device: pickDevice(fetched.posture.devices), reason: fetched.posture.reason }
        : // 오류는 짧게만 캐시한다(ward 가 돌아오면 바로 반영되게).
          { at: now - this.opts.cacheSec * 1000 + 5000, verdict: 'error', device: null, error: fetched.error };
      this.cache.set(key, hit);
      if (this.cache.size > 5000) this.cache.clear();
    }
    const result: ZtResult = {
      mode,
      verdict: hit.verdict,
      // 소프트 호스트는 같은 캐시(사용자+IP)를 써도 호스트마다 다시 계산한다.
      ...decideAccess(mode, hit.verdict, this.opts.failOpen, this.isSoftHost(input.host)),
      device: hit.device,
      cached: !fresh,
      ...(hit.reason ? { reason: hit.reason } : {}),
      ...(hit.error ? { error: hit.error } : {}),
    };

    // 기록은 앱(host)마다 TTL 에 한 번. ward 조회 캐시는 사용자+IP 로 묶지만, 기록까지 그 키로 묶으면 60초 안에
    // 들어간 다른 앱이 목록에 아예 안 보인다(2026-11-04 운영에서 확인: vault·redash 접속이 note 뒤에 숨었다).
    const rkey = `${key}|${input.host.toLowerCase()}`;
    const last = this.recorded.get(rkey);
    if (fresh || last === undefined || now - last >= this.opts.cacheSec * 1000) {
      this.recorded.set(rkey, now);
      if (this.recorded.size > 20000) this.recorded.clear();
      try {
        await this.record(input, result);
      } catch (err) {
        // 기록 실패는 판정에 영향 없지만, 조용히 삼키면 운영에서 "기록이 안 쌓인다"를 못 잡는다(2026-11-04 실제로 겪음).
        console.error('zt_checks 기록 실패', (err as Error).message);
      }
    }
    return result;
  }

  /** 테스트·관리용. */
  clearCache(): void {
    this.cache.clear();
    this.recorded.clear();
  }
}

/** /auth/denied 가 쿼리로 받는 판정(= /auth/verify 의 X-Auth-Denied 값). 이 밖의 값은 무시한다. */
export const DENIED_VERDICTS = ['noncompliant', 'unknown', 'no_device', 'error', 'app_access'] as const;
export type DeniedVerdict = (typeof DENIED_VERDICTS)[number];
/** 안내 문구가 따로 있는 사유. 여기 없는 사유는 쿼리로 와도 무시한다(헤더·기록에는 형식만 맞으면 남는다). */
export const DENIED_REASONS = ['agent_offline'] as const;

export function parseDeniedVerdict(v: unknown): DeniedVerdict | null {
  return typeof v === 'string' && (DENIED_VERDICTS as readonly string[]).includes(v) ? (v as DeniedVerdict) : null;
}
export function parseDeniedReason(v: unknown): string | null {
  const r = parseReason(v);
  return r && (DENIED_REASONS as readonly string[]).includes(r) ? r : null;
}

/** 자동 재시도 간격(초)과 횟수 상한. 상한을 넘기면 버튼만 남긴다(탭을 켜 둔 채 퇴근해도 밤새 두드리지 않게). */
export const DENIED_RETRY_SEC = 20;
export const DENIED_RETRY_MAX = 15;

/** 거부 안내 페이지의 CSP. 외부 자원은 전혀 없고, 인라인 style·script 는 응답마다 새로 만든 nonce 로만 허용한다. */
export function deniedCsp(nonce: string): string {
  return `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
}

function deniedMessage(verdict: string, reason: string | null | undefined, hostname: string | null | undefined): { why: string; fix: string } {
  const wardApp = 'Ward 앱(메뉴바의 방패 아이콘)';
  if (verdict === 'unknown' && reason === 'agent_offline') {
    return {
      why: '이 PC 의 Ward 에이전트가 최근 3분간 서버에 보고하지 않았습니다.',
      fix: `${wardApp}이 실행 중인지 확인하세요. 설치(등록)한 적이 없다면 Ward 앱의 설치 탭에서 설치(등록)를 마치면 됩니다. PC 가 방금 잠자기에서 깨어났다면 1분쯤 기다리면 에이전트가 다시 보고합니다.`,
    };
  }
  if (verdict === 'noncompliant') {
    return {
      why: `기기${hostname ? ` (${escapeHtml(hostname)})` : ''} 의 보안 상태가 회사 기준을 충족하지 않습니다. (디스크 암호화·화면 잠금·방화벽 등)`,
      fix: `${wardApp}을 열어 상태 탭에서 미준수 항목을 확인하고 조치한 뒤 "지금 동기화"를 누르면 1분 안에 다시 접속할 수 있습니다.`,
    };
  }
  if (verdict === 'no_device') {
    return {
      why: '지금 접속한 네트워크 주소와 일치하는 등록 기기가 없습니다. 이 PC 에 Ward 에이전트가 설치·등록되어 있지 않거나, VPN 에 연결되어 있지 않습니다.',
      fix: `VPN(OpenTunnel)이 연결되어 있는지 먼저 확인하세요. 에이전트를 설치한 적이 없다면 ${wardApp}의 설치 탭에서 설치(등록)한 뒤 "지금 동기화"를 누르세요.`,
    };
  }
  if (verdict === 'error') {
    return {
      why: '기기 상태를 확인하는 서버(Ward)에 연결할 수 없습니다.',
      fix: '사용자 쪽에서 고칠 문제가 아닙니다. 잠시 뒤 다시 시도하고, 계속되면 관리자에게 알려 주세요.',
    };
  }
  return {
    why: '기기 상태를 아직 확인하지 못했습니다. 에이전트가 서버와 아직 동기화하지 않았습니다.',
    fix: `${wardApp}을 열어 "지금 동기화"를 누른 뒤 다시 시도해 주세요.`,
  };
}

/**
 * 기기 거부 안내 HTML. /auth/denied(nginx `error_page 403` 경유)·Traefik·OIDC 로그인 관문이 같이 쓴다.
 * 외부 자원 없이 혼자 서는 페이지다. rd(검증을 마친 주소)와 nonce 가 둘 다 있을 때만 "다시 시도" 버튼과 자동 재시도 스크립트를 넣는다.
 * nonce 를 넘겼으면 응답에 deniedCsp(nonce) 를 Content-Security-Policy 로 실어야 한다.
 */
export function deniedPage(opts: {
  verdict: string;
  wardUrl: string;
  reason?: string | null;
  hostname?: string | null;
  /** 돌아갈 주소. 반드시 checkRedirect 를 통과한 값만 넘긴다. */
  rd?: string | null;
  nonce?: string;
}): string {
  const { why, fix } = deniedMessage(opts.verdict, opts.reason, opts.hostname);
  const nonceAttr = opts.nonce ? ` nonce="${escapeHtml(opts.nonce)}"` : '';
  const retry = opts.rd && opts.nonce ? opts.rd : null;
  const code = escapeHtml(opts.verdict) + (opts.reason ? ` / ${escapeHtml(opts.reason)}` : '');
  // 주소는 스크립트 문자열에 넣지 않고 버튼의 href 에서 읽는다(이스케이프를 한 군데서만 한다).
  // 횟수는 sessionStorage 에 둔다 — 이 페이지는 재시도마다 새로 로드되므로 메모리 변수로는 못 센다. 주소가 바뀌거나 10분 넘게 쉬었으면 다시 센다.
  const script = retry
    ? `<script${nonceAttr}>(function(){var a=document.getElementById("retry"),m=document.getElementById("auto");if(!a||!m)return;
var K="gh-denied-retry",MAX=${DENIED_RETRY_MAX},left=${DENIED_RETRY_SEC},u=a.href,n=0,ok=false;
try{var s=JSON.parse(sessionStorage.getItem(K)||"null");if(s&&s.u===u&&Date.now()-s.t<600000)n=s.n|0;sessionStorage.setItem(K,JSON.stringify({u:u,n:n,t:Date.now()}));ok=true}catch(e){}
if(!ok){m.textContent="자동으로 다시 시도할 수 없는 브라우저 설정입니다. 조치한 뒤 위 버튼을 눌러 주세요.";return}
if(n>=MAX){m.textContent="자동 재시도를 "+MAX+"회 했지만 아직 통과하지 못해 멈췄습니다. 조치한 뒤 위 버튼을 눌러 주세요.";return}
function show(){m.textContent=left+"초 뒤 자동으로 다시 시도합니다 ("+(n+1)+"/"+MAX+")"}
show();var t=setInterval(function(){left--;if(left>0){show();return}clearInterval(t);
try{sessionStorage.setItem(K,JSON.stringify({u:u,n:n+1,t:Date.now()}))}catch(e){}
m.textContent="다시 시도하는 중…";location.href=u},1000)})();</script>`
    : '';
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>접속이 차단되었습니다</title>
<style${nonceAttr}>body{font-family:-apple-system,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;background:#f6f7f9;color:#1f2328;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px;max-width:520px;margin:16px}h1{font-size:20px;margin:0 0 12px}p{line-height:1.6;margin:8px 0;overflow-wrap:anywhere}
a.btn{display:inline-block;margin:12px 8px 0 0;padding:10px 16px;border-radius:8px;background:#2563eb;color:#fff;text-decoration:none}a.btn.ghost{background:#fff;color:#2563eb;border:1px solid #2563eb}.muted{color:#6b7280;font-size:13px}</style></head>
<body><div class="card"><h1>🛡️ 기기 확인이 필요합니다</h1>
<p>${why}</p>
<p>${fix}</p>
${retry ? `<a class="btn" id="retry" href="${escapeHtml(retry)}">다시 시도</a>` : ''}<a class="btn${retry ? ' ghost' : ''}" href="${escapeHtml(opts.wardUrl)}">Ward 콘솔 열기</a>
${retry ? `<p class="muted" id="auto" aria-live="polite">조치한 뒤 "다시 시도"를 누르세요.</p>` : ''}
<p class="muted">면제가 필요하면 관리자에게 요청하세요. 판정 코드: ${code}</p></div>${script}</body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
