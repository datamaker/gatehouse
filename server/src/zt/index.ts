import { config } from '../config.js';
import { query } from '../db/pool.js';
import { ZeroTrust, type ZtCheckInput, type ZtResult } from './zt.js';

/** 판정 기록. monitor/enforce 모두 fresh 판정마다 1건(캐시 TTL 안에서는 쌓이지 않는다). */
async function recordCheck(input: ZtCheckInput, r: ZtResult): Promise<void> {
  await query(
    `INSERT INTO zt_checks (email, host, ip, verdict, device_id, device_hostname, mode, allowed, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
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
  },
  recordCheck,
);

/** 요청의 클라이언트 IP: X-Forwarded-For 첫 항목(trustProxy 가 이미 req.ip 에 반영), 없으면 소켓. */
export function clientIp(req: { ip: string; headers: Record<string, string | string[] | undefined> }): string {
  const xff = req.headers['x-forwarded-for'];
  const first = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
  return first || req.ip;
}
