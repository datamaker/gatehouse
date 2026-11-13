import { query } from '../db/pool.js';
import { config } from '../config.js';
import { isAppAllowed, oidcAppKey } from '../auth/appAccess.js';
import { zeroTrust } from '../zt/index.js';
import type { ZtResult } from '../zt/zt.js';

/**
 * OIDC 로 코드를 내주기 전의 공통 관문: 앱 접근 정책 + (실효 모드가 enforce 일 때) 기기 판정.
 * interaction 라우트(로그인 단계)와 OP 세션 재사용 검사(provider 의 policy check) 가 같은 함수를 쓴다 —
 * 한쪽만 막으면 이미 OP 세션이 있는 브라우저는 interaction 을 건너뛰어 그대로 통과한다.
 */

export type GateResult =
  | { ok: true }
  | { ok: false; reason: 'app_access' }
  | { ok: false; reason: 'zt'; zt: ZtResult };

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * 기기 판정으로 막지 않을 클라이언트인지. device grant 를 쓰는 클라이언트(CLI·VPN·에이전트)는 승인하는 브라우저의 IP 와
 * 실제 기기의 IP 가 달라 IP 바인딩이 성립하지 않는다. env 목록으로도 뺄 수 있다.
 */
export function isZtExemptClient(clientId: string, grantTypes: readonly string[], exemptClients: readonly string[]): boolean {
  if (exemptClients.includes(clientId.toLowerCase())) return true;
  return grantTypes.includes(DEVICE_GRANT);
}

export async function oidcGate(
  user: { id: number; email: string },
  clientId: string,
  ip: string,
  /** monitor 판정을 zt_checks 에 남길지. interaction(실제 로그인) 에서만 남긴다. */
  opts: { recordMonitor: boolean },
): Promise<GateResult> {
  if (!(await isAppAllowed(oidcAppKey(clientId), user.id))) return { ok: false, reason: 'app_access' };
  if (zeroTrust.mode === 'off') return { ok: true };

  const { rows } = await query<{ grant_types: string[] }>('SELECT grant_types FROM oidc_clients WHERE client_id = $1', [clientId]);
  const monitorOnly = isZtExemptClient(clientId, rows[0]?.grant_types ?? [], config.zt.oidcExemptClients);
  const input = { email: user.email, host: `oidc:${clientId}`, ip, monitorOnly };

  if (zeroTrust.effectiveMode(user.email, monitorOnly) !== 'enforce') {
    // 기록만: ward 응답을 기다리느라 로그인을 늦추지 않는다.
    if (opts.recordMonitor) zeroTrust.check(input).catch(() => {});
    return { ok: true };
  }
  const zt = await zeroTrust.check(input);
  return zt.allowed ? { ok: true } : { ok: false, reason: 'zt', zt };
}
