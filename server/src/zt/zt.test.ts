import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { ZeroTrust, decide, deniedPage, fetchPosture, pickDevice, type ZtCheckInput, type ZtDevice, type ZtOptions, type ZtResult } from './zt.js';

// 가짜 ward. 이메일별로 응답을 정해 두고, 호출 횟수·지연·오류를 흉내 낸다.
let server: http.Server;
let wardUrl = '';
let calls = 0;
let delayMs = 0;
let failWith: number | null = null;
const SECRET = 'test-secret';

const devices: Record<'mine' | 'old' | 'other', ZtDevice> = {
  mine: { id: 'dev-1', hostname: 'mbp', platform: 'macos', posture_status: 'compliant', last_seen_at: '2026-11-03T10:00:00Z', last_ip: '10.0.0.5', ip_match: true, online: true },
  old: { id: 'dev-0', hostname: 'old', platform: 'windows', posture_status: 'noncompliant', last_seen_at: '2026-10-01T10:00:00Z', last_ip: '10.0.0.5', ip_match: true, online: false },
  other: { id: 'dev-2', hostname: 'other', platform: 'macos', posture_status: 'compliant', last_seen_at: '2026-11-03T11:00:00Z', last_ip: '10.0.0.9', ip_match: false, online: true },
};

before(async () => {
  server = http.createServer((req, res) => {
    calls++;
    const url = new URL(req.url ?? '/', 'http://x');
    const respond = () => {
      if (req.headers['x-ward-secret'] !== SECRET) {
        res.writeHead(401); res.end(JSON.stringify({ error: 'bad secret' })); return;
      }
      if (failWith) { res.writeHead(failWith); res.end('boom'); return; }
      const email = url.searchParams.get('email');
      res.setHeader('content-type', 'application/json');
      if (email === 'good@datasee.co.kr') { res.end(JSON.stringify({ devices: [devices.mine, devices.other, devices.old], verdict: 'compliant' })); return; }
      if (email === 'bad@datasee.co.kr') { res.end(JSON.stringify({ devices: [{ ...devices.mine, posture_status: 'noncompliant' }], verdict: 'noncompliant' })); return; }
      if (email === 'nodev@datasee.co.kr') { res.end(JSON.stringify({ devices: [devices.other], verdict: 'no_device' })); return; }
      res.writeHead(404); res.end(JSON.stringify({ error: 'no such user' }));
    };
    if (delayMs) setTimeout(respond, delayMs); else respond();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address() as { port: number };
  wardUrl = `http://127.0.0.1:${addr.port}`;
});
after(() => server.close());

function opts(over: Partial<ZtOptions> = {}): ZtOptions {
  return { mode: 'enforce', wardUrl, wardSecret: SECRET, failOpen: true, cacheSec: 60, timeoutMs: 300, exemptEmails: [], exemptHosts: [], ...over };
}
const input = (email: string, host = 'in.datasee.co.kr', ip = '10.0.0.5'): ZtCheckInput => ({ email, host, ip });

describe('decide', () => {
  test('off/monitor 는 항상 통과, enforce 는 compliant 만', () => {
    assert.equal(decide('off', 'noncompliant', false), true);
    assert.equal(decide('monitor', 'no_device', false), true);
    assert.equal(decide('enforce', 'compliant', false), true);
    assert.equal(decide('enforce', 'noncompliant', true), false);
    assert.equal(decide('enforce', 'unknown', true), false);
    assert.equal(decide('enforce', 'no_device', true), false);
    assert.equal(decide('enforce', 'exempt', false), true);
  });
  test('ward 오류는 fail-open 설정을 따른다', () => {
    assert.equal(decide('enforce', 'error', true), true);
    assert.equal(decide('enforce', 'error', false), false);
  });
});

describe('pickDevice', () => {
  test('ip_match 인 기기 중 최신', () => {
    assert.equal(pickDevice([devices.old, devices.other, devices.mine])?.id, 'dev-1');
    assert.equal(pickDevice([devices.other]), null);
  });
});

describe('fetchPosture', () => {
  test('정상·404·시크릿 불일치·타임아웃', async () => {
    const ok = await fetchPosture({ wardUrl, wardSecret: SECRET, timeoutMs: 300 }, 'good@datasee.co.kr', '10.0.0.5');
    assert.ok(ok.ok && ok.posture.verdict === 'compliant' && ok.posture.devices.length === 3);
    const none = await fetchPosture({ wardUrl, wardSecret: SECRET, timeoutMs: 300 }, 'ghost@datasee.co.kr', '1.1.1.1');
    assert.ok(none.ok && none.posture.verdict === 'no_device');
    const bad = await fetchPosture({ wardUrl, wardSecret: 'wrong', timeoutMs: 300 }, 'good@datasee.co.kr', '10.0.0.5');
    assert.ok(!bad.ok && /401/.test(bad.error));
    delayMs = 600;
    const slow = await fetchPosture({ wardUrl, wardSecret: SECRET, timeoutMs: 200 }, 'good@datasee.co.kr', '10.0.0.5');
    delayMs = 0;
    assert.ok(!slow.ok && /timeout/.test(slow.error));
  });
});

describe('ZeroTrust.check', () => {
  test('off 면 ward 를 부르지 않는다', async () => {
    const before = calls;
    const r = await new ZeroTrust(opts({ mode: 'off' })).check(input('good@datasee.co.kr'));
    assert.equal(r.allowed, true); assert.equal(r.verdict, 'exempt'); assert.equal(calls, before);
  });

  test('monitor: 기록하고 통과 (미준수여도)', async () => {
    const recorded: ZtResult[] = [];
    const zt = new ZeroTrust(opts({ mode: 'monitor' }), (_i, r) => { recorded.push(r); });
    const r = await zt.check(input('bad@datasee.co.kr'));
    assert.equal(r.allowed, true); assert.equal(r.verdict, 'noncompliant'); assert.equal(r.device?.id, 'dev-1');
    assert.equal(recorded.length, 1);
  });

  test('enforce: compliant 통과, noncompliant·no_device 차단', async () => {
    const zt = new ZeroTrust(opts());
    assert.equal((await zt.check(input('good@datasee.co.kr'))).allowed, true);
    const bad = await zt.check(input('bad@datasee.co.kr'));
    assert.equal(bad.allowed, false); assert.equal(bad.verdict, 'noncompliant');
    const nodev = await zt.check(input('nodev@datasee.co.kr'));
    assert.equal(nodev.allowed, false); assert.equal(nodev.verdict, 'no_device'); assert.equal(nodev.device, null);
    const ghost = await zt.check(input('ghost@datasee.co.kr'));
    assert.equal(ghost.allowed, false); assert.equal(ghost.verdict, 'no_device');
  });

  test('캐시: 같은 email+ip 는 TTL 안에서 ward 를 다시 부르지 않고, 기록도 1건만', async () => {
    const recorded: ZtResult[] = [];
    const zt = new ZeroTrust(opts(), (_i, r) => { recorded.push(r); });
    const before = calls;
    await zt.check(input('good@datasee.co.kr'));
    await zt.check(input('good@datasee.co.kr'));
    const third = await zt.check(input('good@datasee.co.kr'));
    assert.equal(calls - before, 1); assert.equal(third.cached, true); assert.equal(recorded.length, 1);
    await zt.check(input('good@datasee.co.kr', 'in.datasee.co.kr', '10.0.0.6')); // 다른 IP 는 새 조회
    assert.equal(calls - before, 2);
  });

  test('캐시: 다른 앱(host)은 ward 를 다시 안 부르지만 기록은 앱마다 1건', async () => {
    const recorded: ZtCheckInput[] = [];
    const zt = new ZeroTrust(opts(), (i) => { recorded.push(i); });
    const before = calls;
    await zt.check(input('good@datasee.co.kr', 'note.datasee.co.kr'));
    const vault = await zt.check(input('good@datasee.co.kr', 'vault.datasee.co.kr'));
    await zt.check(input('good@datasee.co.kr', 'VAULT.datasee.co.kr')); // 대소문자만 다르면 같은 앱
    await zt.check(input('good@datasee.co.kr', 'note.datasee.co.kr'));
    assert.equal(calls - before, 1, 'ward 조회는 사용자+IP 로 한 번');
    assert.equal(vault.cached, true);
    assert.equal(vault.verdict, 'compliant');
    assert.deepEqual(recorded.map((r) => r.host), ['note.datasee.co.kr', 'vault.datasee.co.kr']);
  });

  test('ward 장애: fail-open 통과 / fail-closed 차단, 오류는 짧게만 캐시', async () => {
    failWith = 500;
    const open = await new ZeroTrust(opts({ failOpen: true })).check(input('good@datasee.co.kr'));
    assert.equal(open.allowed, true); assert.equal(open.verdict, 'error'); assert.match(open.error ?? '', /500/);
    const closed = new ZeroTrust(opts({ failOpen: false }));
    const c1 = await closed.check(input('good@datasee.co.kr'));
    assert.equal(c1.allowed, false); assert.equal(c1.verdict, 'error');
    failWith = null;
    // 오류 캐시는 5초. 바로 다시 부르면 캐시(여전히 error)… 테스트에선 clearCache 로 복구 확인
    closed.clearCache();
    assert.equal((await closed.check(input('good@datasee.co.kr'))).allowed, true);
  });

  test('타임아웃도 장애로 취급한다', async () => {
    delayMs = 600;
    const r = await new ZeroTrust(opts({ failOpen: false, timeoutMs: 200 })).check(input('good@datasee.co.kr'));
    delayMs = 0;
    assert.equal(r.allowed, false); assert.match(r.error ?? '', /timeout/);
  });

  test('면제: 이메일·호스트(와일드카드)', async () => {
    const zt = new ZeroTrust(opts({ exemptEmails: ['bad@datasee.co.kr'], exemptHosts: ['*.public.datasee.co.kr', 'status.datasee.co.kr'] }));
    assert.equal((await zt.check(input('bad@datasee.co.kr'))).verdict, 'exempt');
    assert.equal((await zt.check(input('nodev@datasee.co.kr', 'x.public.datasee.co.kr'))).allowed, true);
    assert.equal((await zt.check(input('nodev@datasee.co.kr', 'status.datasee.co.kr'))).allowed, true);
    assert.equal((await zt.check(input('nodev@datasee.co.kr', 'in.datasee.co.kr'))).allowed, false);
  });
});

describe('deniedPage', () => {
  test('사유별 문구와 HTML 이스케이프', () => {
    assert.match(deniedPage({ verdict: 'no_device', wardUrl: 'https://ward.datasee.co.kr' }), /설치·등록되어 있지 않/);
    assert.match(deniedPage({ verdict: 'noncompliant', wardUrl: 'https://w', hostname: '<x>' }), /&lt;x&gt;/);
    assert.match(deniedPage({ verdict: 'error', wardUrl: 'https://w' }), /연결할 수 없습니다/);
  });
});
