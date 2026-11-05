import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { config } from '../config.js';
import { migrate } from '../db/migrate.js';
import { pool, query } from '../db/pool.js';
import { createSession, getSessionUser } from './session.js';

// 실제 Postgres(docker-compose.dev.yml, :5435)를 쓴다. 가짜 DB 로는 CTE 안의 UPDATE 가
// 정확히 한 번 도는지, LEAST 로 상한이 잡히는지 같은 핵심을 검증할 수 없다.
const EMAIL = 'session-test@datasee.co.kr';
let userId = 0;
const saved = { idle: config.sessionIdleHours, max: config.sessionMaxHours, touch: config.sessionTouchMinutes };

type Row = { expires_at: Date; absolute_expires_at: Date; last_seen_at: Date };
async function row(token: string): Promise<Row> {
  const { rows } = await query<Row>(
    `SELECT expires_at, absolute_expires_at, last_seen_at FROM sessions
     WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
    [Buffer.from(token)],
  );
  assert.ok(rows[0], 'session row missing');
  return rows[0];
}
/** 실제 시각이 기대 시각 ±tolerance 초 안인지. */
function near(actual: Date, expectedMs: number, toleranceSec = 5) {
  assert.ok(Math.abs(actual.getTime() - expectedMs) < toleranceSec * 1000, `${actual.toISOString()} vs ${new Date(expectedMs).toISOString()}`);
}
const h = (n: number) => n * 3600 * 1000;
const m = (n: number) => n * 60 * 1000;

before(async () => {
  await migrate();
  await query('DELETE FROM users WHERE email = $1', [EMAIL]);
  const { rows } = await query<{ id: number }>(
    `INSERT INTO users (google_sub, email, hd, name) VALUES ($1, $2, 'datasee.co.kr', 'tester') RETURNING id`,
    [`test-${Date.now()}`, EMAIL],
  );
  userId = rows[0].id;
  config.sessionIdleHours = 24;
  config.sessionMaxHours = 168;
  config.sessionTouchMinutes = 10;
});
after(async () => {
  await query('DELETE FROM users WHERE email = $1', [EMAIL]);
  Object.assign(config, { sessionIdleHours: saved.idle, sessionMaxHours: saved.max, sessionTouchMinutes: saved.touch });
  await pool.end();
});

describe('sliding session', () => {
  test('생성: 유휴 만료 = now+idle, 절대 상한 = now+max, 조회되면 사용자 반환', async () => {
    const token = await createSession(userId, '10.0.0.1', 'ua');
    const r = await row(token);
    near(r.expires_at, Date.now() + h(24));
    near(r.absolute_expires_at, Date.now() + h(168));
    const user = await getSessionUser(token);
    assert.equal(user?.email, EMAIL);
  });

  test('touch 간격 안의 조회는 DB 를 건드리지 않는다', async () => {
    const token = await createSession(userId, undefined, undefined);
    await query(
      `UPDATE sessions SET last_seen_at = now() - interval '5 minutes', expires_at = now() + interval '1 hour'
       WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
      [Buffer.from(token)],
    );
    assert.ok(await getSessionUser(token));
    const r = await row(token);
    near(r.expires_at, Date.now() + h(1));
    near(r.last_seen_at, Date.now() - m(5));
  });

  test('touch 간격이 지난 조회는 유휴 만료를 now+idle 로 민다', async () => {
    const token = await createSession(userId, undefined, undefined);
    await query(
      `UPDATE sessions SET last_seen_at = now() - interval '11 minutes', expires_at = now() + interval '1 hour'
       WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
      [Buffer.from(token)],
    );
    assert.ok(await getSessionUser(token));
    const r = await row(token);
    near(r.expires_at, Date.now() + h(24));
    near(r.last_seen_at, Date.now());
  });

  test('연장해도 절대 상한은 넘지 않는다', async () => {
    const token = await createSession(userId, undefined, undefined);
    await query(
      `UPDATE sessions SET last_seen_at = now() - interval '1 hour',
         expires_at = now() + interval '10 minutes', absolute_expires_at = now() + interval '30 minutes'
       WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
      [Buffer.from(token)],
    );
    assert.ok(await getSessionUser(token));
    const r = await row(token);
    near(r.expires_at, Date.now() + m(30));
    assert.equal(r.expires_at.getTime(), r.absolute_expires_at.getTime());
  });

  test('유휴 만료 또는 절대 상한이 지나면 null, 그리고 연장되지 않는다', async () => {
    const idle = await createSession(userId, undefined, undefined);
    await query(
      `UPDATE sessions SET expires_at = now() - interval '1 second', last_seen_at = now() - interval '1 day'
       WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
      [Buffer.from(idle)],
    );
    assert.equal(await getSessionUser(idle), null);
    assert.ok((await row(idle)).expires_at.getTime() < Date.now(), 'expired session must not be revived');

    const capped = await createSession(userId, undefined, undefined);
    await query(
      `UPDATE sessions SET absolute_expires_at = now() - interval '1 second', last_seen_at = now() - interval '1 day'
       WHERE token_hash = encode(sha256($1::bytea), 'hex')`,
      [Buffer.from(capped)],
    );
    assert.equal(await getSessionUser(capped), null);
  });

  test('비활성 사용자는 세션이 살아 있어도 null', async () => {
    const token = await createSession(userId, undefined, undefined);
    await query('UPDATE users SET is_active = false WHERE id = $1', [userId]);
    try {
      assert.equal(await getSessionUser(token), null);
    } finally {
      await query('UPDATE users SET is_active = true WHERE id = $1', [userId]);
    }
  });

  test('정리 잡은 유휴 만료·상한 만료 둘 다 지운다', async () => {
    const a = await createSession(userId, undefined, undefined);
    const b = await createSession(userId, undefined, undefined);
    const c = await createSession(userId, undefined, undefined);
    await query(`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE token_hash = encode(sha256($1::bytea), 'hex')`, [Buffer.from(a)]);
    await query(`UPDATE sessions SET absolute_expires_at = now() - interval '1 second' WHERE token_hash = encode(sha256($1::bytea), 'hex')`, [Buffer.from(b)]);
    await query('DELETE FROM sessions WHERE expires_at < now() OR absolute_expires_at < now()');
    const { rows } = await query<{ n: number }>(
      `SELECT count(*)::int AS n FROM sessions WHERE token_hash IN (
         encode(sha256($1::bytea), 'hex'), encode(sha256($2::bytea), 'hex'), encode(sha256($3::bytea), 'hex'))`,
      [Buffer.from(a), Buffer.from(b), Buffer.from(c)],
    );
    assert.equal(rows[0].n, 1);
  });
});
