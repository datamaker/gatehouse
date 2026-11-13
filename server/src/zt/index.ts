import { config } from '../config.js';
import { query } from '../db/pool.js';
import { ZeroTrust, type ZtCheckInput, type ZtResult } from './zt.js';

/** 판정 기록. monitor/enforce 모두 사용자+IP+앱(host) 마다 캐시 TTL 에 1건. */
async function recordCheck(input: ZtCheckInput, r: ZtResult): Promise<void> {
  await query(
    `INSERT INTO zt_checks (email, host, ip, verdict, device_id, device_hostname, mode, allowed, error, reason, restricted)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      input.email,
      input.host,
      input.ip,
      r.verdict,
      r.device?.id ?? null,
      r.device?.hostname ?? null,
      r.mode,
      r.allowed,
      r.error ?? null,
      r.reason ?? null,
      r.restricted,
    ],
  );
}

export const zeroTrust = new ZeroTrust(
  {
    mode: config.zt.mode,
    wardUrl: config.zt.wardUrl,
    wardSecret: config.zt.wardSecret,
    failOpen: config.zt.failOpen,
    cacheSec: config.zt.cacheSec,
    timeoutMs: config.zt.timeoutMs,
    exemptEmails: config.zt.exemptEmails,
    exemptHosts: config.zt.exemptHosts,
    softHosts: config.zt.softHosts,
    enforceEmails: config.zt.enforceEmails,
  },
  recordCheck,
);

/** 요청의 클라이언트 IP. fastify trustProxy=1 이 nginx 한 홉만 믿고 X-Forwarded-For 의 마지막 항목(nginx 가 $remote_addr 로 쓴 값)을 req.ip 로 준다.
 *  헤더를 직접 읽지 않는다 — 첫 항목을 읽으면 브라우저가 붙인 값으로 남의 기기 IP 를 사칭할 수 있다(2026-11-04 운영에서 확인). */
export function clientIp(req: { ip: string }): string {
  return req.ip;
}

/** oidc-provider(Koa) 쪽처럼 fastify 를 거치지 않는 raw 요청용. clientIp 와 같은 규칙: nginx 가 쓴 X-Forwarded-For 의 마지막 항목만 믿는다. */
export function rawClientIp(req: { headers: Record<string, string | string[] | undefined>; socket: { remoteAddress?: string } }): string {
  const xff = req.headers['x-forwarded-for'];
  const last = (Array.isArray(xff) ? xff.join(',') : (xff ?? '')).split(',').pop()?.trim();
  return last || req.socket.remoteAddress || '';
}
