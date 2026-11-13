import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { FastifyInstance } from 'fastify';

// 라우트 통합 테스트: 실제 Postgres(:5435) + 가짜 ward.
// config.ts 는 import 시점에 env 를 읽으므로, 가짜 ward 를 먼저 띄우고 env 를 넣은 뒤 동적으로 import 한다.
const EMAIL = 'verify-test@datasee.co.kr';
const SECRET = 'verify-test-secret';
const SOFT = 'ward.datasee.co.kr';
const HARD = 'note.datasee.co.kr';
const LOCKED = 'locked-verify-test.datasee.co.kr';

let ward: http.Server;
let wardCalls = 0;
/** 가짜 ward 가 다음에 줄 응답. */
let posture: Record<string, unknown> = { devices: [], verdict: 'noncompliant' };
let app: FastifyInstance;
let cookieName = '';
let token = '';
let userId = 0;
let db: typeof import('../db/pool.js');
let clearZt: () => void;

before(async () => {
  ward = http.createServer((_req, res) => {
    wardCalls++;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(posture));
  });
  await new Promise<void>((r) => ward.listen(0, '127.0.0.1', r));
  const port = (ward.address() as { port: number }).port;

  process.env.GATEHOUSE_ZT_MODE = 'enforce';
  process.env.GATEHOUSE_WARD_URL = `http://127.0.0.1:${port}`;
  process.env.GATEHOUSE_WARD_SECRET = SECRET;
  process.env.GATEHOUSE_ZT_SOFT_HOSTS = SOFT;
  process.env.GATEHOUSE_ZT_EXEMPT_HOSTS = '';
  process.env.GATEHOUSE_ZT_EXEMPT_EMAILS = '';
  process.env.GATEHOUSE_PUBLIC_URL = '';
  process.env.GATEHOUSE_ALLOWED_DOMAINS = 'datasee.co.kr';
  process.env.GATEHOUSE_REDIRECT_DOMAINS = '';
  process.env.GATEHOUSE_COOKIE_DOMAIN = '';

  const { migrate } = await import('../db/migrate.js');
  db = await import('../db/pool.js');
  const session = await import('../auth/session.js');
  const { registerVerifyRoutes } = await import('./verify.js');
  const { zeroTrust } = await import('../zt/index.js');
  const { default: Fastify } = await import('fastify');
  const { default: cookie } = await import('@fastify/cookie');
  clearZt = () => zeroTrust.clearCache();

  await migrate();
  await cleanup();
  const { rows } = await db.query<{ id: number }>(
    `INSERT INTO users (google_sub, email, hd, name) VALUES ($1, $2, 'datasee.co.kr', 'tester') RETURNING id`,
    [`verify-test-${Date.now()}`, EMAIL],
  );
  userId = rows[0].id;
  // 접근이 제한된 앱(허용 사용자 없음) — 앱 접근 거부 경로용.
  await db.query(`INSERT INTO app_policies (app_key, mode) VALUES ($1, 'restricted')`, [LOCKED]);
  token = await session.createSession(userId, '127.0.0.1', 'test');
  cookieName = session.SESSION_COOKIE;

  app = Fastify({ trustProxy: 1 });
  await app.register(cookie);
  registerVerifyRoutes(app);
});

async function cleanup(): Promise<void> {
  await db.query('DELETE FROM zt_checks WHERE email = $1', [EMAIL]);
  await db.query('DELETE FROM app_policies WHERE app_key = $1', [LOCKED]);
  await db.query('DELETE FROM users WHERE email = $1', [EMAIL]);
}

after(async () => {
  await cleanup();
  await app.close();
  await db.pool.end();
  ward.close();
});

const verify = (host: string, path = '/auth/verify', withCookie = true) =>
  app.inject({
    method: 'GET',
    url: path,
    headers: {
      'x-forwarded-host': host,
      'x-forwarded-proto': 'https',
      'x-forwarded-uri': '/page?x=1',
      ...(withCookie ? { cookie: `${cookieName}=${token}` } : {}),
    },
  });

const denied = (qs: string, withCookie = true) =>
  app.inject({ method: 'GET', url: `/auth/denied${qs}`, headers: withCookie ? { cookie: `${cookieName}=${token}` } : {} });

async function lastCheck(host: string) {
  const { rows } = await db.query<{ verdict: string; allowed: boolean; restricted: boolean | null; reason: string | null; mode: string }>(
    'SELECT verdict, allowed, restricted, reason, mode FROM zt_checks WHERE email = $1 AND host = $2 ORDER BY id DESC LIMIT 1',
    [EMAIL, host],
  );
  return rows[0];
}

describe('/auth/verify: 사유 헤더와 소프트 호스트', () => {
  test('거부: X-Auth-Denied 옆에 X-Auth-Denied-Reason, 기록에도 reason', async () => {
    clearZt();
    posture = { devices: [], verdict: 'unknown', reason: 'agent_offline', online: false, last_seen_at: '2026-11-13T00:00:00Z' };
    const res = await verify(HARD);
    assert.equal(res.statusCode, 403);
    assert.equal(res.headers['x-auth-denied'], 'unknown');
    assert.equal(res.headers['x-auth-denied-reason'], 'agent_offline');
    assert.equal(res.headers['x-auth-device-status'], 'unknown');
    assert.equal(res.headers['x-auth-device-restricted'], undefined, '거부 응답에는 싣지 않는다');
    assert.deepEqual(await lastCheck(HARD), { verdict: 'unknown', allowed: false, restricted: false, reason: 'agent_offline', mode: 'enforce' });
  });

  test('사유가 없거나 형식이 틀리면 X-Auth-Denied-Reason 을 싣지 않는다', async () => {
    clearZt();
    posture = { devices: [], verdict: 'noncompliant' };
    const plain = await verify(HARD);
    assert.equal(plain.statusCode, 403);
    assert.equal(plain.headers['x-auth-denied'], 'noncompliant');
    assert.equal(plain.headers['x-auth-denied-reason'], undefined);
    clearZt();
    posture = { devices: [], verdict: 'unknown', reason: 'Bad Reason\r\nX-Evil: 1' };
    const bad = await verify(HARD);
    assert.equal(bad.statusCode, 403);
    assert.equal(bad.headers['x-auth-denied-reason'], undefined);
    assert.equal(bad.headers['x-evil'], undefined);
    assert.equal((await lastCheck(HARD)).reason, null);
  });

  test('소프트 호스트: 거부 판정이어도 200 + Restricted 1, Status 는 실제 판정, 기록은 allowed·restricted', async () => {
    clearZt();
    posture = { devices: [], verdict: 'noncompliant' };
    const res = await verify(SOFT);
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['x-auth-device-restricted'], '1');
    assert.equal(res.headers['x-auth-device-status'], 'noncompliant');
    assert.equal(res.headers['x-auth-email'], EMAIL);
    assert.equal(res.headers['x-auth-denied'], undefined);
    assert.deepEqual(await lastCheck(SOFT), { verdict: 'noncompliant', allowed: true, restricted: true, reason: null, mode: 'enforce' });
    // 같은 캐시로 일반 호스트는 여전히 403
    assert.equal((await verify(HARD)).statusCode, 403);
  });

  test('준수 기기: 소프트·일반 호스트 모두 200 + Restricted 0', async () => {
    clearZt();
    posture = { devices: [], verdict: 'compliant' };
    for (const host of [SOFT, HARD]) {
      const res = await verify(host);
      assert.equal(res.statusCode, 200, host);
      assert.equal(res.headers['x-auth-device-restricted'], '0', host);
      assert.equal(res.headers['x-auth-device-status'], 'compliant', host);
    }
    assert.deepEqual(await lastCheck(SOFT), { verdict: 'compliant', allowed: true, restricted: false, reason: null, mode: 'enforce' });
  });

  test('앱 접근 정책 거부는 소프트 여부와 무관하게 403 app_access (기기 판정 전)', async () => {
    clearZt();
    const before = wardCalls;
    const res = await verify(LOCKED);
    assert.equal(res.statusCode, 403);
    assert.equal(res.headers['x-auth-denied'], 'app_access');
    assert.equal(res.headers['x-auth-denied-reason'], undefined);
    assert.equal(wardCalls, before);
  });

  test('/auth/traefik: 거부면 헤더 + CSP 가 붙은 안내 페이지(원래 주소로 재시도), 소프트 호스트는 200 + Restricted 1', async () => {
    clearZt();
    posture = { devices: [], verdict: 'unknown', reason: 'agent_offline' };
    const res = await verify(HARD, '/auth/traefik');
    assert.equal(res.statusCode, 403);
    assert.equal(res.headers['x-auth-denied'], 'unknown');
    assert.equal(res.headers['x-auth-denied-reason'], 'agent_offline');
    assert.match(res.body, /최근 3분간 서버에 보고하지 않았습니다/);
    assert.match(res.body, /id="retry" href="https:\/\/note\.datasee\.co\.kr\/page\?x=1"/);
    assert.match(String(res.headers['content-security-policy']), /script-src 'nonce-/);
    const soft = await verify(SOFT, '/auth/traefik');
    assert.equal(soft.statusCode, 200);
    assert.equal(soft.headers['x-auth-device-restricted'], '1');
  });
});

describe('/auth/denied', () => {
  const RD = 'https://note.datasee.co.kr/doc/1?a=1&b=2';
  const q = (v?: string, r?: string, rd: string | null = RD) =>
    '?' + [rd ? `rd=${encodeURIComponent(rd)}` : '', v !== undefined ? `v=${encodeURIComponent(v)}` : '', r !== undefined ? `r=${encodeURIComponent(r)}` : ''].filter(Boolean).join('&');

  test('ward 를 조회하지 않고 판정 기록도 남기지 않는다(판정별·세션 유무 모두)', async () => {
    clearZt();
    posture = { devices: [], verdict: 'compliant' }; // 다시 판정했다면 통과로 보고 rd 로 돌려보냈을 것이다
    const before = wardCalls;
    const { rows: c0 } = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM zt_checks WHERE email = $1', [EMAIL]);
    for (const v of ['noncompliant', 'unknown', 'no_device', 'error', 'bogus', undefined]) {
      for (const withCookie of [true, false]) {
        const res = await denied(q(v, 'agent_offline'), withCookie);
        assert.equal(res.statusCode, 403, `${v} ${withCookie}`);
      }
    }
    assert.equal(wardCalls, before);
    const { rows: c1 } = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM zt_checks WHERE email = $1', [EMAIL]);
    assert.equal(c1[0].n, c0[0].n);
  });

  test('판정·사유별 문구', async () => {
    const offline = await denied(q('unknown', 'agent_offline'));
    assert.match(offline.body, /이 PC 의 Ward 에이전트가 최근 3분간 서버에 보고하지 않았습니다/);
    assert.match(offline.body, /설치 탭에서 설치\(등록\)/);
    assert.match(offline.body, /1분쯤 기다리면/);
    const unknown = await denied(q('unknown'));
    assert.match(unknown.body, /아직 동기화하지 않았습니다/);
    assert.doesNotMatch(unknown.body, /최근 3분간/);
    assert.match((await denied(q('noncompliant'))).body, /보안 상태가 회사 기준을 충족하지 않습니다/);
    const nodev = await denied(q('no_device'));
    assert.match(nodev.body, /일치하는 등록 기기가 없습니다/);
    assert.match(nodev.body, /VPN 에 연결되어 있지 않습니다/);
    assert.match((await denied(q('error'))).body, /연결할 수 없습니다/);
    for (const v of ['noncompliant', 'unknown', 'no_device', 'error']) {
      const res = await denied(q(v));
      assert.ok(res.body.includes(`판정 코드: ${v}`), v);
      assert.match(res.body, /Ward 콘솔 열기/);
    }
  });

  test('재시도 버튼·자동 재시도 스크립트·CSP(nonce 일치)·캐시 금지', async () => {
    const res = await denied(q('noncompliant'));
    assert.match(res.body, /id="retry" href="https:\/\/note\.datasee\.co\.kr\/doc\/1\?a=1&amp;b=2">다시 시도</);
    const csp = String(res.headers['content-security-policy']);
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    assert.ok(nonce && nonce.length >= 16);
    assert.match(csp, /default-src 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline/);
    assert.ok(res.body.includes(`<script nonce="${nonce}">`));
    assert.ok(res.body.includes(`<style nonce="${nonce}">`));
    assert.equal(res.body.split('<script').length - 1, 1);
    assert.match(res.body, /left=20/);
    assert.match(res.body, /MAX=15/);
    assert.equal(res.headers['cache-control'], 'no-store');
    // nonce 는 응답마다 다르다
    const again = String((await denied(q('noncompliant'))).headers['content-security-policy']);
    assert.notEqual(again, csp);
  });

  test('잘못된 v·r 은 무시한다(문구·판정 코드에 흘러들지 않는다)', async () => {
    const res = await denied(q('<script>alert(1)</script>', '"><img src=x>'));
    assert.equal(res.statusCode, 403);
    assert.match(res.body, /판정 코드: unknown</);
    assert.doesNotMatch(res.body, /alert\(1\)|<img/);
    // 형식은 맞지만 허용 목록에 없는 사유, 통과 판정을 흉내 낸 v
    const other = await denied(q('unknown', 'made_up_reason'));
    assert.doesNotMatch(other.body, /made_up_reason|최근 3분간/);
    const compliant = await denied(q('compliant'));
    assert.equal(compliant.statusCode, 403);
    assert.match(compliant.body, /판정 코드: unknown</);
    // 사유는 unknown 판정에만 붙는다
    assert.doesNotMatch((await denied(q('noncompliant', 'agent_offline'))).body, /agent_offline|최근 3분간/);
    // 같은 이름이 두 번 오면(배열) 받지 않는다
    const dup = await denied(`?rd=${encodeURIComponent(RD)}&v=noncompliant&v=error&r=agent_offline&r=agent_offline`);
    assert.match(dup.body, /판정 코드: unknown</);
  });

  test('rd 가 없거나 검증에 걸리면 재시도 컨트롤이 없다', async () => {
    for (const rd of [null, 'https://evil.example/x', 'https://datasee.co.kr.evil.example/', 'javascript:alert(1)', '//evil.example/x', '/\\evil.example', 'https://note.datasee.co.kr/a\\b']) {
      const res = await denied(q('noncompliant', undefined, rd));
      assert.equal(res.statusCode, 403, String(rd));
      assert.doesNotMatch(res.body, /id="retry"|<script|다시 시도<|evil\.example/, String(rd));
      assert.match(res.body, /Ward 콘솔 열기/);
      assert.match(res.body, /보안 상태가 회사 기준/);
    }
    const dup = await denied(`?rd=${encodeURIComponent(RD)}&rd=${encodeURIComponent(RD)}&v=noncompliant`);
    assert.doesNotMatch(dup.body, /id="retry"|<script/);
    // 상대 경로 rd 는 gatehouse 자신으로 돌아가는 것이라 허용
    assert.match((await denied(q('noncompliant', undefined, '/oidc-interaction/abc'))).body, /id="retry" href="\/oidc-interaction\/abc"/);
  });

  test('앱 접근 거부: v 와 무관하게 서버가 다시 확인해 앱 거부 페이지, 권한이 생기면 rd 로 복귀', async () => {
    const lockedRd = `https://${LOCKED}/x`;
    for (const v of ['app_access', 'noncompliant', undefined]) {
      const res = await denied(q(v, undefined, lockedRd));
      assert.equal(res.statusCode, 403, String(v));
      assert.equal(res.headers['x-auth-denied'], 'app_access');
      assert.match(res.body, /이 앱에 접근할 권한이 없습니다/);
      assert.doesNotMatch(res.body, /기기 확인이 필요합니다/);
    }
    // 세션이 없으면 다시 확인할 수 없다 — v=app_access 를 믿고 앱 거부 페이지를 보여 준다(돌려보내지 않는다).
    const anon = await denied(q('app_access', undefined, lockedRd), false);
    assert.equal(anon.statusCode, 403);
    assert.match(anon.body, /이 앱에 접근할 권한이 없습니다/);
    // 허용된 앱인데 v=app_access 로 왔다 = 그 사이 권한이 추가됐다 → 바로 복귀
    const back = await denied(q('app_access'));
    assert.equal(back.statusCode, 302);
    assert.equal(back.headers.location, RD);
    // 기기 판정 거부는 권한이 있어도 자동으로 302 하지 않는다(판정은 rd 쪽 /auth/verify 가 한다)
    assert.equal((await denied(q('noncompliant'))).statusCode, 403);
  });
});
