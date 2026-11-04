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
}

export interface ZtResult {
  /** 판정에 쓴 모드. off 면 아무것도 안 한 것. */
  mode: ZtMode;
  /** ward 가 준 verdict. 조회 실패면 'error', 면제면 'exempt'. */
  verdict: ZtVerdict | 'error' | 'exempt';
  /** 통과 여부. monitor 는 항상 true. */
  allowed: boolean;
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
    const body = (await res.json()) as Partial<WardPosture>;
    const verdict = body.verdict;
    if (!verdict || !['compliant', 'noncompliant', 'unknown', 'no_device'].includes(verdict)) {
      return { ok: false, error: 'ward 응답에 verdict 가 없습니다' };
    }
    return { ok: true, posture: { devices: Array.isArray(body.devices) ? body.devices : [], verdict } };
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

function matchHost(host: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) return host === pattern.slice(2) || host.endsWith(pattern.slice(1));
  return host === pattern;
}

export class ZeroTrust {
  private cache = new Map<string, { at: number; result: ZtResult }>();
  /** email|ip|host → 마지막 기록 시각. */
  private recorded = new Map<string, number>();

  constructor(
    private opts: ZtOptions,
    /** fresh 판정마다, 그리고 캐시를 탔어도 그 앱(host)의 TTL 안 첫 접속이면 호출된다(기록용). 실패해도 판정에는 영향이 없어야 한다. */
    private record: (input: ZtCheckInput, result: ZtResult) => Promise<void> | void = () => {},
  ) {}

  get mode(): ZtMode {
    return this.opts.mode;
  }

  isExempt(email: string, host: string): boolean {
    const e = email.toLowerCase();
    if (this.opts.exemptEmails.includes(e)) return true;
    const h = host.toLowerCase();
    return this.opts.exemptHosts.some((p) => matchHost(h, p));
  }

  async check(input: ZtCheckInput): Promise<ZtResult> {
    const mode = this.opts.mode;
    if (mode === 'off') return { mode, verdict: 'exempt', allowed: true, device: null, cached: false };
    if (this.isExempt(input.email, input.host)) {
      return { mode, verdict: 'exempt', allowed: true, device: null, cached: false };
    }

    const email = input.email.toLowerCase();
    const key = `${email}|${input.ip}`;
    const now = Date.now();
    const hit = this.cache.get(key);
    let result: ZtResult;
    let fresh = false;
    if (hit && now - hit.at < this.opts.cacheSec * 1000) {
      result = { ...hit.result, cached: true };
    } else {
      fresh = true;
      const fetched = await fetchPosture(this.opts, input.email, input.ip);
      if (fetched.ok) {
        const verdict = fetched.posture.verdict;
        result = {
          mode,
          verdict,
          allowed: decide(mode, verdict, this.opts.failOpen),
          device: pickDevice(fetched.posture.devices),
          cached: false,
        };
      } else {
        result = {
          mode,
          verdict: 'error',
          allowed: decide(mode, 'error', this.opts.failOpen),
          device: null,
          cached: false,
          error: fetched.error,
        };
      }
      // 오류는 짧게만 캐시한다(ward 가 돌아오면 바로 반영되게).
      this.cache.set(key, { at: fetched.ok ? now : now - this.opts.cacheSec * 1000 + 5000, result });
      if (this.cache.size > 5000) this.cache.clear();
    }

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

/** 거부 안내 HTML. nginx `error_page 403` 로 보여 준다. */
export function deniedPage(opts: { verdict: string; wardUrl: string; hostname?: string | null }): string {
  const reason =
    opts.verdict === 'no_device'
      ? '이 PC 에 ward 에이전트가 설치·등록되어 있지 않거나, 지금 접속한 네트워크 주소와 등록된 기기의 주소가 다릅니다.'
      : opts.verdict === 'noncompliant'
        ? `기기${opts.hostname ? ` (${escapeHtml(opts.hostname)})` : ''} 의 보안 상태가 회사 기준을 충족하지 않습니다. (디스크 암호화·화면 잠금·방화벽 등)`
        : opts.verdict === 'error'
          ? '기기 상태를 확인하는 서버에 연결할 수 없습니다.'
          : '기기 상태를 아직 확인하지 못했습니다. 에이전트가 서버와 동기화한 뒤 다시 시도해 주세요.';
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>접속이 차단되었습니다</title>
<style>body{font-family:-apple-system,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;background:#f6f7f9;color:#1f2328;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px;max-width:520px;margin:16px}h1{font-size:20px;margin:0 0 12px}p{line-height:1.6;margin:8px 0}
a.btn{display:inline-block;margin-top:12px;padding:10px 16px;border-radius:8px;background:#2563eb;color:#fff;text-decoration:none}.muted{color:#6b7280;font-size:13px}</style></head>
<body><div class="card"><h1>🛡️ 기기 확인이 필요합니다</h1>
<p>${reason}</p>
<p>Ward 앱(메뉴바의 방패 아이콘)을 열어 상태 탭에서 미준수 항목을 확인하고 조치한 뒤 "지금 동기화"를 누르면 1분 안에 다시 접속할 수 있습니다.</p>
<a class="btn" href="${escapeHtml(opts.wardUrl)}">Ward 콘솔 열기</a>
<p class="muted">면제가 필요하면 관리자에게 요청하세요. 판정 코드: ${escapeHtml(opts.verdict)}</p></div></body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
