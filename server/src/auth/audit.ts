import { query } from '../db/pool.js';

/**
 * 관리자 작업 감사 로그. 관리 API 의 모든 변경(사용자 활성/권한, 세션 종료, OIDC 클라이언트, 앱 정책)을 남긴다.
 * detail 에는 시크릿 값을 절대 넣지 않는다. 기록 실패는 작업 자체를 실패시키지 않지만 조용히 삼키지도 않는다.
 */
export async function logAdminEvent(
  actor: { id: number; email: string },
  action: string,
  target: string,
  detail: Record<string, unknown> = {},
  ip?: string,
): Promise<void> {
  await query(
    `INSERT INTO admin_events (actor_id, actor_email, action, target, detail, ip)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [actor.id, actor.email, action, target, JSON.stringify(detail), ip ?? null],
  ).catch((err) => console.error('admin_events 기록 실패', (err as Error).message));
}
