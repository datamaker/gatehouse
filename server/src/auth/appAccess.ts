import { query } from '../db/pool.js';

/**
 * 앱별 접근 정책.
 *
 * app_key 는 forward-auth 가 보호하는 호스트(소문자, 예: `vault.datasee.co.kr`) 또는 `oidc:<client_id>`.
 * 정책 행이 없거나 mode 가 `all` 이면 활성 사용자 전원 허용, `restricted` 면 app_access 에 있는 사용자만.
 * forward-auth 는 요청마다 불리므로 정책은 메모리에 잠깐(30초 이하) 캐시하고, 관리자가 바꾸면 바로 비운다.
 */

export type AppMode = 'all' | 'restricted';

export interface AppPolicy {
  mode: AppMode;
  userIds: ReadonlySet<number>;
}

const APP_KEY = /^(oidc:[\w.~:-]{1,200}|[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:\d{1,5})?)$/;

/** 키를 한 가지 모양(소문자, 공백 없음)으로. 호스트는 대소문자를 가리지 않는다. */
export function normalizeAppKey(key: string): string {
  return key.trim().toLowerCase();
}

export function isValidAppKey(key: string): boolean {
  return APP_KEY.test(key);
}

export function oidcAppKey(clientId: string): string {
  return normalizeAppKey(`oidc:${clientId}`);
}

/** 순수 판정. 정책이 없으면(null) 전원 허용. */
export function decideAppAccess(policy: AppPolicy | null, userId: number): boolean {
  if (!policy || policy.mode !== 'restricted') return true;
  return policy.userIds.has(userId);
}

const CACHE_MS = 30_000;
const cache = new Map<string, { at: number; policy: AppPolicy | null }>();

async function loadPolicy(appKey: string): Promise<AppPolicy | null> {
  const { rows } = await query<{ mode: AppMode }>('SELECT mode FROM app_policies WHERE app_key = $1', [appKey]);
  if (!rows[0]) return null;
  if (rows[0].mode !== 'restricted') return { mode: 'all', userIds: new Set() };
  const users = await query<{ user_id: number }>('SELECT user_id FROM app_access WHERE app_key = $1', [appKey]);
  return { mode: 'restricted', userIds: new Set(users.rows.map((r) => r.user_id)) };
}

/** 이 사용자가 이 앱에 들어갈 수 있는지. DB 오류는 삼키지 않는다(판정 불가를 허용으로 바꾸지 않기 위해). */
export async function isAppAllowed(appKey: string, userId: number): Promise<boolean> {
  const key = normalizeAppKey(appKey);
  const now = Date.now();
  const hit = cache.get(key);
  let policy: AppPolicy | null;
  if (hit && now - hit.at < CACHE_MS) {
    policy = hit.policy;
  } else {
    policy = await loadPolicy(key);
    // 키(호스트)는 요청에서 오므로 캐시가 끝없이 자라지 않게 막는다.
    if (cache.size > 2000) cache.clear();
    cache.set(key, { at: now, policy });
  }
  return decideAppAccess(policy, userId);
}

/** 관리자가 정책·허용 사용자를 바꿨을 때. */
export function invalidateAppAccess(appKey?: string): void {
  if (appKey) cache.delete(normalizeAppKey(appKey));
  else cache.clear();
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** 앱 접근 거부 안내. 기기 거부(deniedPage)와 문구·조치가 다르다 — 기기를 고쳐도 풀리지 않는다. */
export function appDeniedPage(opts: { app: string; email?: string | null }): string {
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>접근 권한이 없습니다</title>
<style>body{font-family:-apple-system,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;background:#f6f7f9;color:#1f2328;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px;max-width:520px;margin:16px}h1{font-size:20px;margin:0 0 12px}p{line-height:1.6;margin:8px 0;overflow-wrap:anywhere}
.muted{color:#6b7280;font-size:13px}</style></head>
<body><div class="card"><h1>🔒 이 앱에 접근할 권한이 없습니다</h1>
<p><strong>${escapeHtml(opts.app)}</strong> 은(는) 허용된 사용자만 쓸 수 있도록 제한되어 있습니다.${opts.email ? ` 지금 로그인한 계정은 <strong>${escapeHtml(opts.email)}</strong> 입니다.` : ''}</p>
<p>업무에 필요하면 관리자에게 이 앱의 접근 권한을 요청하세요. 권한이 추가되면 이 페이지를 새로 고치면 됩니다.</p>
<p class="muted">기기 상태와는 무관한 차단입니다. 판정 코드: app_access</p></div></body></html>`;
}
