import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { migrate } from '../db/migrate.js';
import { pool, query } from '../db/pool.js';
import {
  appDeniedPage,
  decideAppAccess,
  invalidateAppAccess,
  isAppAllowed,
  isValidAppKey,
  normalizeAppKey,
  oidcAppKey,
} from './appAccess.js';
import { isZtExemptClient } from '../oidc/gate.js';

describe('decideAppAccess (순수 판정)', () => {
  test('정책이 없거나 all 이면 전원 허용', () => {
    assert.equal(decideAppAccess(null, 1), true);
    assert.equal(decideAppAccess({ mode: 'all', userIds: new Set() }, 1), true);
    assert.equal(decideAppAccess({ mode: 'all', userIds: new Set([2]) }, 1), true);
  });
  test('restricted 는 목록에 있는 사용자만', () => {
    const p = { mode: 'restricted' as const, userIds: new Set([1, 3]) };
    assert.equal(decideAppAccess(p, 1), true);
    assert.equal(decideAppAccess(p, 2), false);
    assert.equal(decideAppAccess({ mode: 'restricted', userIds: new Set() }, 1), false); // 빈 목록 = 전원 차단
  });
});

describe('app_key', () => {
  test('정규화·검증', () => {
    assert.equal(normalizeAppKey(' Vault.Datasee.co.kr '), 'vault.datasee.co.kr');
    assert.equal(oidcAppKey('Lookout-Web'), 'oidc:lookout-web');
    assert.ok(isValidAppKey('vault.datasee.co.kr'));
    assert.ok(isValidAppKey('localhost:8080'));
    assert.ok(isValidAppKey('oidc:vault-cli'));
    assert.ok(!isValidAppKey(''));
    assert.ok(!isValidAppKey('Vault.datasee.co.kr')); // 정규화 전 대문자
    assert.ok(!isValidAppKey('vault.datasee.co.kr/path'));
    assert.ok(!isValidAppKey('a b'));
    assert.ok(!isValidAppKey('oidc:'));
    assert.ok(!isValidAppKey('<script>'));
  });
});

describe('isZtExemptClient (OIDC 기기 판정 제외)', () => {
  const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
  test('device grant 를 쓰는 클라이언트와 env 목록은 제외, 웹 클라이언트는 대상', () => {
    assert.equal(isZtExemptClient('lookout', ['authorization_code'], []), false);
    assert.equal(isZtExemptClient('opentunnel', [DEVICE], []), true);
    assert.equal(isZtExemptClient('vault-cli', ['authorization_code', DEVICE], []), true);
    assert.equal(isZtExemptClient('Lookout', ['authorization_code'], ['lookout']), true);
    assert.equal(isZtExemptClient('ghost', [], []), false);
  });
});

describe('appDeniedPage', () => {
  test('기기 거부와 구분되는 문구, HTML 이스케이프', () => {
    const html = appDeniedPage({ app: '<b>vault</b>', email: 'a@datasee.co.kr' });
    assert.match(html, /접근할 권한이 없습니다/);
    assert.match(html, /app_access/);
    assert.match(html, /&lt;b&gt;vault&lt;\/b&gt;/);
    assert.doesNotMatch(html, /Ward 콘솔/);
  });
});

// 실제 Postgres(:5435): 정책 테이블(마이그레이션 008)·캐시·무효화.
describe('isAppAllowed (DB + 캐시)', () => {
  const APP = 'appaccess-test.datasee.co.kr';
  const OIDC = 'oidc:appaccess-test';
  const EMAILS = ['appaccess-a@datasee.co.kr', 'appaccess-b@datasee.co.kr'];
  let a = 0;
  let b = 0;

  before(async () => {
    await migrate();
    await query('DELETE FROM app_policies WHERE app_key = ANY($1)', [[APP, OIDC]]);
    await query('DELETE FROM users WHERE email = ANY($1)', [EMAILS]);
    const { rows } = await query<{ id: number }>(
      `INSERT INTO users (google_sub, email, hd, name)
       VALUES ($1, $2, 'datasee.co.kr', 'a'), ($3, $4, 'datasee.co.kr', 'b') RETURNING id`,
      [`appaccess-a-${Date.now()}`, EMAILS[0], `appaccess-b-${Date.now()}`, EMAILS[1]],
    );
    [a, b] = rows.map((r) => r.id);
    invalidateAppAccess();
  });
  after(async () => {
    await query('DELETE FROM app_policies WHERE app_key = ANY($1)', [[APP, OIDC]]);
    await query('DELETE FROM users WHERE email = ANY($1)', [EMAILS]);
    await pool.end();
  });

  test('정책 행이 없으면 전원 허용 (배포 직후 동작 불변)', async () => {
    assert.equal(await isAppAllowed(APP, a), true);
    assert.equal(await isAppAllowed(APP, b), true);
  });

  test('restricted 로 바꾸고 무효화하면 목록 사용자만, 호스트 대소문자 무시', async () => {
    await query(`INSERT INTO app_policies (app_key, mode) VALUES ($1, 'restricted')`, [APP]);
    await query('INSERT INTO app_access (app_key, user_id) VALUES ($1, $2)', [APP, a]);
    // 무효화 전에는 캐시(30초)가 이전 판정을 준다
    assert.equal(await isAppAllowed(APP, b), true);
    invalidateAppAccess(APP);
    assert.equal(await isAppAllowed(APP, a), true);
    assert.equal(await isAppAllowed(APP, b), false);
    assert.equal(await isAppAllowed(APP.toUpperCase(), b), false);
  });

  test('목록에서 빼면 차단, all 로 돌리면 다시 전원 허용', async () => {
    await query('DELETE FROM app_access WHERE app_key = $1 AND user_id = $2', [APP, a]);
    invalidateAppAccess(APP);
    assert.equal(await isAppAllowed(APP, a), false);
    await query(`UPDATE app_policies SET mode = 'all' WHERE app_key = $1`, [APP]);
    invalidateAppAccess(APP);
    assert.equal(await isAppAllowed(APP, a), true);
    assert.equal(await isAppAllowed(APP, b), true);
  });

  test('OIDC 클라이언트 키도 같은 규칙, 다른 앱 정책과 섞이지 않는다', async () => {
    await query(`INSERT INTO app_policies (app_key, mode) VALUES ($1, 'restricted')`, [OIDC]);
    await query('INSERT INTO app_access (app_key, user_id) VALUES ($1, $2)', [OIDC, b]);
    invalidateAppAccess();
    assert.equal(await isAppAllowed(oidcAppKey('AppAccess-Test'), b), true);
    assert.equal(await isAppAllowed(oidcAppKey('appaccess-test'), a), false);
    assert.equal(await isAppAllowed(APP, a), true);
  });

  test('사용자가 지워지면 허용 목록에서도 빠진다(FK cascade)', async () => {
    await query('DELETE FROM users WHERE id = $1', [b]);
    const { rows } = await query<{ n: number }>('SELECT count(*)::int AS n FROM app_access WHERE app_key = $1', [OIDC]);
    assert.equal(rows[0].n, 0);
  });
});
