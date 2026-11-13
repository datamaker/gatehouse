import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';
import { migrate } from '../db/migrate.js';
import { pool, query } from '../db/pool.js';
import { registerInternalRoutes } from './internal.js';

// 실제 Postgres(:5435). users.revoked_before 컬럼(마이그레이션 007)까지 같이 검증한다.
const EMAIL = 'internal-test@datasee.co.kr';
const SECRET = 'internal-test-secret';
let app: FastifyInstance;
let off: FastifyInstance;
let userId = 0;

before(async () => {
  await migrate();
  await query('DELETE FROM users WHERE email = $1', [EMAIL]);
  const { rows } = await query<{ id: number }>(
    `INSERT INTO users (google_sub, email, hd, name) VALUES ($1, $2, 'datasee.co.kr', 'tester') RETURNING id`,
    [`internal-test-${Date.now()}`, EMAIL],
  );
  userId = rows[0].id;
  app = Fastify();
  registerInternalRoutes(app, SECRET);
  off = Fastify();
  registerInternalRoutes(off, ''); // 시크릿 미설정
});
after(async () => {
  await query('DELETE FROM users WHERE email = $1', [EMAIL]);
  await app.close();
  await off.close();
  await pool.end();
});

const get = (email: string, secret?: string, target = app) =>
  target.inject({
    method: 'GET',
    url: `/internal/account?email=${encodeURIComponent(email)}`,
    headers: secret === undefined ? {} : { 'x-gatehouse-secret': secret },
  });

describe('GET /internal/account', () => {
  test('시크릿이 없으면 라우트 자체가 없다(404)', async () => {
    const res = await get(EMAIL, SECRET, off);
    assert.equal(res.statusCode, 404);
  });

  test('시크릿 누락·불일치는 401 (길이가 달라도)', async () => {
    assert.equal((await get(EMAIL)).statusCode, 401);
    assert.equal((await get(EMAIL, 'wrong')).statusCode, 401);
    assert.equal((await get(EMAIL, SECRET + 'x')).statusCode, 401);
    assert.equal((await get(EMAIL, SECRET.slice(0, -1))).statusCode, 401);
    assert.equal((await get(EMAIL, '')).statusCode, 401);
    // 모르는 이메일이어도 시크릿이 틀리면 401 (존재 여부를 흘리지 않는다)
    assert.equal((await get('ghost@datasee.co.kr', 'wrong')).statusCode, 401);
  });

  test('활성 사용자: active=true, revoked_before=null, 이메일 대소문자 무시', async () => {
    const res = await get(EMAIL.toUpperCase(), SECRET);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.json(), { email: EMAIL, active: true, revoked_before: null });
  });

  test('모르는 이메일은 404 {"active":false}', async () => {
    const res = await get('ghost@datasee.co.kr', SECRET);
    assert.equal(res.statusCode, 404);
    assert.deepEqual(res.json(), { active: false });
  });

  test('email 이 없으면 400', async () => {
    const res = await app.inject({ method: 'GET', url: '/internal/account', headers: { 'x-gatehouse-secret': SECRET } });
    assert.equal(res.statusCode, 400);
  });

  test('세션 종료·비활성화가 찍은 revoked_before 를 ISO 8601 로 돌려준다', async () => {
    const t0 = Date.now();
    await query('UPDATE users SET revoked_before = now() WHERE id = $1', [userId]);
    const a = (await get(EMAIL, SECRET)).json() as { active: boolean; revoked_before: string };
    assert.equal(a.active, true);
    assert.match(a.revoked_before, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.ok(Math.abs(new Date(a.revoked_before).getTime() - t0) < 5000);

    await query('UPDATE users SET is_active = false WHERE id = $1', [userId]);
    const b = (await get(EMAIL, SECRET)).json() as { active: boolean; revoked_before: string };
    assert.equal(b.active, false);
    assert.equal(b.revoked_before, a.revoked_before);
  });
});
