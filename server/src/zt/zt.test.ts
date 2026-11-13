import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { DENIED_RETRY_MAX, DENIED_RETRY_SEC, ZeroTrust, decide, decideAccess, deniedCsp, deniedPage, effectiveMode, fetchPosture, parseDeniedReason, parseDeniedVerdict, parseReason, pickDevice, type ZtCheckInput, type ZtDevice, type ZtOptions, type ZtResult } from './zt.js';

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
      // 에이전트가 최근에 보고하지 않은 기기: ward 가 unknown 에 사유를 붙인다.
      if (email === 'offline@datasee.co.kr') { res.end(JSON.stringify({ devices: [{ ...devices.mine, online: false }], verdict: 'unknown', reason: 'agent_offline', online: false, last_seen_at: '2026-11-03T10:00:00Z' })); return; }
      // 형식이 틀린 사유(헤더 주입 시도 포함)는 버려져야 한다.
      if (email === 'badreason@datasee.co.kr') { res.end(JSON.stringify({ devices: [], verdict: 'unknown', reason: 'Agent-Offline\r\nX-Evil: 1' })); return; }
      if (email === 'numreason@datasee.co.kr') { res.end(JSON.stringify({ devices: [], verdict: 'unknown', reason: 42 })); return; }
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

describe('effectiveMode (사용자별 enforce)', () => {
  const LIST = ['bad@datasee.co.kr', 'nodev@datasee.co.kr'];
  test('전역 monitor: 목록 사용자만 enforce (대소문자 무시)', () => {
    assert.equal(effectiveMode('monitor', LIST, 'bad@datasee.co.kr'), 'enforce');
    assert.equal(effectiveMode('monitor', LIST, 'BAD@Datasee.co.kr'), 'enforce');
    assert.equal(effectiveMode('monitor', LIST, 'good@datasee.co.kr'), 'monitor');
    assert.equal(effectiveMode('monitor', [], 'bad@datasee.co.kr'), 'monitor');
  });
  test('전역 off 는 목록이 있어도 off, 전역 enforce 는 전원 enforce', () => {
    assert.equal(effectiveMode('off', LIST, 'bad@datasee.co.kr'), 'off');
    assert.equal(effectiveMode('enforce', LIST, 'good@datasee.co.kr'), 'enforce');
    assert.equal(effectiveMode('enforce', [], 'good@datasee.co.kr'), 'enforce');
  });
});

describe('ZeroTrust: 선택 사용자만 enforce', () => {
  test('전역 monitor + 목록: 목록 사용자는 차단되고 기록의 mode 는 enforce, 나머지는 monitor 로 통과', async () => {
    const recorded: { email: string; mode: string; allowed: boolean }[] = [];
    const zt = new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['Bad@Datasee.co.kr'] }), (i, r) => {
      recorded.push({ email: i.email, mode: r.mode, allowed: r.allowed });
    });
    assert.deepEqual([...zt.enforceEmails], ['bad@datasee.co.kr']);
    assert.equal(zt.mode, 'monitor');
    assert.equal(zt.effectiveMode('BAD@datasee.co.kr'), 'enforce');
    assert.equal(zt.effectiveMode('nodev@datasee.co.kr'), 'monitor');

    const bad = await zt.check(input('bad@datasee.co.kr'));
    assert.equal(bad.mode, 'enforce'); assert.equal(bad.allowed, false); assert.equal(bad.verdict, 'noncompliant');
    const nodev = await zt.check(input('nodev@datasee.co.kr'));
    assert.equal(nodev.mode, 'monitor'); assert.equal(nodev.allowed, true); assert.equal(nodev.verdict, 'no_device');
    assert.deepEqual(recorded, [
      { email: 'bad@datasee.co.kr', mode: 'enforce', allowed: false },
      { email: 'nodev@datasee.co.kr', mode: 'monitor', allowed: true },
    ]);
  });

  test('목록 사용자라도 준수 기기면 통과', async () => {
    const zt = new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['good@datasee.co.kr'] }));
    const r = await zt.check(input('good@datasee.co.kr'));
    assert.equal(r.mode, 'enforce'); assert.equal(r.allowed, true);
  });

  test('전역 off 면 목록이 있어도 ward 를 부르지 않고 통과', async () => {
    const before = calls;
    const zt = new ZeroTrust(opts({ mode: 'off', enforceEmails: ['bad@datasee.co.kr'] }));
    const r = await zt.check(input('bad@datasee.co.kr'));
    assert.equal(r.mode, 'off'); assert.equal(r.allowed, true); assert.equal(calls, before);
  });

  test('면제 이메일·호스트는 enforce 목록보다 우선', async () => {
    const zt = new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['bad@datasee.co.kr', 'nodev@datasee.co.kr'], exemptEmails: ['bad@datasee.co.kr'], exemptHosts: ['status.datasee.co.kr'] }));
    assert.equal((await zt.check(input('bad@datasee.co.kr'))).verdict, 'exempt');
    assert.equal((await zt.check(input('nodev@datasee.co.kr', 'status.datasee.co.kr'))).allowed, true);
    assert.equal((await zt.check(input('nodev@datasee.co.kr'))).allowed, false);
  });

  test('fail-open 설정은 enforce 대상에게도 그대로', async () => {
    failWith = 500;
    try {
      const open = await new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['good@datasee.co.kr'], failOpen: true })).check(input('good@datasee.co.kr'));
      assert.equal(open.mode, 'enforce'); assert.equal(open.verdict, 'error'); assert.equal(open.allowed, true);
      const closed = await new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['good@datasee.co.kr'], failOpen: false })).check(input('good@datasee.co.kr'));
      assert.equal(closed.allowed, false);
      // 목록 밖 사용자는 fail-closed 여도 monitor 라 통과
      const other = await new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['good@datasee.co.kr'], failOpen: false })).check(input('bad@datasee.co.kr'));
      assert.equal(other.mode, 'monitor'); assert.equal(other.allowed, true);
    } finally {
      failWith = null;
    }
  });

  test('monitorOnly(device grant OIDC 클라이언트): enforce 대상이어도 기록만, 같은 캐시를 써도 경로별로 다시 판정', async () => {
    const recorded: { host: string; mode: string; allowed: boolean }[] = [];
    const zt = new ZeroTrust(opts({ mode: 'monitor', enforceEmails: ['bad@datasee.co.kr'] }), (i, r) => {
      recorded.push({ host: i.host, mode: r.mode, allowed: r.allowed });
    });
    const before = calls;
    const cli = await zt.check({ ...input('bad@datasee.co.kr', 'oidc:opentunnel'), monitorOnly: true });
    assert.equal(cli.mode, 'monitor'); assert.equal(cli.allowed, true); assert.equal(cli.verdict, 'noncompliant');
    // 같은 사용자+IP 의 웹 앱 접속은 캐시된 ward 결과로도 enforce 로 막혀야 한다
    const web = await zt.check(input('bad@datasee.co.kr', 'vault.datasee.co.kr'));
    assert.equal(web.cached, true); assert.equal(web.mode, 'enforce'); assert.equal(web.allowed, false);
    assert.equal(calls - before, 1);
    assert.deepEqual(recorded, [
      { host: 'oidc:opentunnel', mode: 'monitor', allowed: true },
      { host: 'vault.datasee.co.kr', mode: 'enforce', allowed: false },
    ]);
    // 전역 enforce 에서도 monitorOnly 는 막지 않는다
    const g = await new ZeroTrust(opts({ mode: 'enforce' })).check({ ...input('bad@datasee.co.kr', 'oidc:opentunnel'), monitorOnly: true });
    assert.equal(g.mode, 'monitor'); assert.equal(g.allowed, true);
  });
});

describe('ward 사유(reason)', () => {
  test('parseReason: 소문자·밑줄 1~40자만', () => {
    assert.equal(parseReason('agent_offline'), 'agent_offline');
    assert.equal(parseReason('a'.repeat(40)), 'a'.repeat(40));
    for (const bad of ['', 'a'.repeat(41), 'Agent_offline', 'agent-offline', 'agent offline', 'agent_offline\n', 'a1', 'x\r\nY: 1', 42, null, undefined, ['agent_offline'], {}]) {
      assert.equal(parseReason(bad), undefined, JSON.stringify(bad));
    }
  });

  test('fetchPosture: 사유를 싣고, 형식이 틀리면 버린다(verdict 는 그대로)', async () => {
    const o = { wardUrl, wardSecret: SECRET, timeoutMs: 300 };
    const off = await fetchPosture(o, 'offline@datasee.co.kr', '10.0.0.5');
    assert.ok(off.ok && off.posture.verdict === 'unknown' && off.posture.reason === 'agent_offline');
    const bad = await fetchPosture(o, 'badreason@datasee.co.kr', '10.0.0.5');
    assert.ok(bad.ok && bad.posture.verdict === 'unknown' && !('reason' in bad.posture));
    const num = await fetchPosture(o, 'numreason@datasee.co.kr', '10.0.0.5');
    assert.ok(num.ok && !('reason' in num.posture));
    const good = await fetchPosture(o, 'good@datasee.co.kr', '10.0.0.5');
    assert.ok(good.ok && !('reason' in good.posture));
  });

  test('check: 사유가 결과·기록·캐시된 결과에 모두 남는다', async () => {
    const recorded: ZtResult[] = [];
    const zt = new ZeroTrust(opts(), (_i, r) => { recorded.push(r); });
    const before = calls;
    const first = await zt.check(input('offline@datasee.co.kr'));
    assert.equal(first.allowed, false); assert.equal(first.verdict, 'unknown'); assert.equal(first.reason, 'agent_offline');
    const cached = await zt.check(input('offline@datasee.co.kr', 'vault.datasee.co.kr'));
    assert.equal(calls - before, 1); assert.equal(cached.cached, true); assert.equal(cached.reason, 'agent_offline');
    assert.deepEqual(recorded.map((r) => r.reason), ['agent_offline', 'agent_offline']);
    const none = await zt.check(input('bad@datasee.co.kr'));
    assert.equal('reason' in none, false);
    assert.equal('reason' in (await zt.check(input('badreason@datasee.co.kr'))), false);
  });
});

describe('소프트 호스트(막지 않고 제한)', () => {
  test('decideAccess: enforce + 거부 판정 + 소프트 → 통과·제한, 그 외에는 제한 아님', () => {
    for (const v of ['noncompliant', 'unknown', 'no_device'] as const) {
      assert.deepEqual(decideAccess('enforce', v, true, true), { allowed: true, restricted: true }, v);
      assert.deepEqual(decideAccess('enforce', v, true, false), { allowed: false, restricted: false }, v);
      assert.deepEqual(decideAccess('monitor', v, true, true), { allowed: true, restricted: false }, v);
      assert.deepEqual(decideAccess('off', v, true, true), { allowed: true, restricted: false }, v);
    }
    assert.deepEqual(decideAccess('enforce', 'compliant', true, true), { allowed: true, restricted: false });
    assert.deepEqual(decideAccess('enforce', 'exempt', false, true), { allowed: true, restricted: false });
    // ward 장애: fail-open 이면 원래 통과라 제한 아님, fail-closed 면 거부될 것이므로 소프트 호스트에서는 제한 접근
    assert.deepEqual(decideAccess('enforce', 'error', true, true), { allowed: true, restricted: false });
    assert.deepEqual(decideAccess('enforce', 'error', false, true), { allowed: true, restricted: true });
    assert.deepEqual(decideAccess('enforce', 'error', false, false), { allowed: false, restricted: false });
  });

  test('enforce: 소프트 호스트는 미준수여도 통과(restricted), 다른 호스트는 같은 캐시로도 차단. 판정·기록은 그대로', async () => {
    const recorded: { host: string; verdict: string; allowed: boolean; restricted: boolean }[] = [];
    const zt = new ZeroTrust(opts({ softHosts: ['ward.datasee.co.kr', '*.soft.datasee.co.kr'] }), (i, r) => {
      recorded.push({ host: i.host, verdict: r.verdict, allowed: r.allowed, restricted: r.restricted });
    });
    assert.equal(zt.isSoftHost('WARD.datasee.co.kr'), true);
    assert.equal(zt.isSoftHost('a.soft.datasee.co.kr'), true);
    assert.equal(zt.isSoftHost('soft.datasee.co.kr'), true);
    assert.equal(zt.isSoftHost('notward.datasee.co.kr'), false);
    assert.equal(zt.isExempt('bad@datasee.co.kr', 'ward.datasee.co.kr'), false, '소프트 호스트는 면제가 아니다');

    const before = calls;
    const soft = await zt.check(input('bad@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(soft.mode, 'enforce'); assert.equal(soft.verdict, 'noncompliant');
    assert.equal(soft.allowed, true); assert.equal(soft.restricted, true); assert.equal(soft.device?.id, 'dev-1');
    const hard = await zt.check(input('bad@datasee.co.kr', 'vault.datasee.co.kr'));
    assert.equal(hard.allowed, false); assert.equal(hard.restricted, false); assert.equal(hard.cached, true);
    const wild = await zt.check(input('bad@datasee.co.kr', 'x.soft.datasee.co.kr'));
    assert.equal(wild.allowed, true); assert.equal(wild.restricted, true);
    assert.equal(calls - before, 1, 'ward 조회는 한 번');
    assert.deepEqual(recorded, [
      { host: 'ward.datasee.co.kr', verdict: 'noncompliant', allowed: true, restricted: true },
      { host: 'vault.datasee.co.kr', verdict: 'noncompliant', allowed: false, restricted: false },
      { host: 'x.soft.datasee.co.kr', verdict: 'noncompliant', allowed: true, restricted: true },
    ]);

    const nodev = await zt.check(input('nodev@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(nodev.verdict, 'no_device'); assert.equal(nodev.allowed, true); assert.equal(nodev.restricted, true);
    const offline = await zt.check(input('offline@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(offline.restricted, true); assert.equal(offline.reason, 'agent_offline');
  });

  test('준수 기기는 소프트 호스트에서도 restricted=false', async () => {
    const r = await new ZeroTrust(opts({ softHosts: ['ward.datasee.co.kr'] })).check(input('good@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(r.allowed, true); assert.equal(r.restricted, false); assert.equal(r.verdict, 'compliant');
  });

  test('monitor 는 소프트 호스트여도 restricted=false, 사용자별 enforce 대상만 restricted', async () => {
    const zt = new ZeroTrust(opts({ mode: 'monitor', softHosts: ['ward.datasee.co.kr'], enforceEmails: ['nodev@datasee.co.kr'] }));
    const mon = await zt.check(input('bad@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(mon.mode, 'monitor'); assert.equal(mon.allowed, true); assert.equal(mon.restricted, false);
    const enf = await zt.check(input('nodev@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(enf.mode, 'enforce'); assert.equal(enf.allowed, true); assert.equal(enf.restricted, true);
  });

  test('면제가 소프트보다 우선: 면제 호스트·면제 이메일은 판정 자체를 하지 않는다', async () => {
    const before = calls;
    const zt = new ZeroTrust(opts({ softHosts: ['ward.datasee.co.kr'], exemptHosts: ['ward.datasee.co.kr'], exemptEmails: ['nodev@datasee.co.kr'] }));
    const host = await zt.check(input('bad@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(host.verdict, 'exempt'); assert.equal(host.allowed, true); assert.equal(host.restricted, false);
    const mail = await zt.check(input('nodev@datasee.co.kr', 'ward.datasee.co.kr'));
    assert.equal(mail.verdict, 'exempt'); assert.equal(mail.restricted, false);
    assert.equal(calls, before);
  });

  test('ward 장애 + fail-closed: 소프트 호스트는 제한 접근으로 통과, fail-open 은 제한 아님', async () => {
    failWith = 500;
    try {
      const closed = await new ZeroTrust(opts({ failOpen: false, softHosts: ['ward.datasee.co.kr'] })).check(input('good@datasee.co.kr', 'ward.datasee.co.kr'));
      assert.equal(closed.verdict, 'error'); assert.equal(closed.allowed, true); assert.equal(closed.restricted, true);
      const open = await new ZeroTrust(opts({ failOpen: true, softHosts: ['ward.datasee.co.kr'] })).check(input('good@datasee.co.kr', 'ward.datasee.co.kr'));
      assert.equal(open.allowed, true); assert.equal(open.restricted, false);
    } finally {
      failWith = null;
    }
  });

  test('off·일반 결과에도 restricted 필드는 항상 있다(false)', async () => {
    assert.equal((await new ZeroTrust(opts({ mode: 'off', softHosts: ['ward.datasee.co.kr'] })).check(input('bad@datasee.co.kr', 'ward.datasee.co.kr'))).restricted, false);
    assert.equal((await new ZeroTrust(opts()).check(input('bad@datasee.co.kr'))).restricted, false);
  });
});

describe('deniedPage', () => {
  const W = 'https://ward.datasee.co.kr';
  test('사유별 문구와 HTML 이스케이프', () => {
    assert.match(deniedPage({ verdict: 'no_device', wardUrl: W }), /설치·등록되어 있지 않/);
    assert.match(deniedPage({ verdict: 'no_device', wardUrl: W }), /VPN/);
    assert.match(deniedPage({ verdict: 'noncompliant', wardUrl: 'https://w', hostname: '<x>' }), /&lt;x&gt;/);
    assert.match(deniedPage({ verdict: 'noncompliant', wardUrl: W }), /회사 기준을 충족하지 않습니다/);
    assert.match(deniedPage({ verdict: 'error', wardUrl: 'https://w' }), /연결할 수 없습니다/);
    assert.match(deniedPage({ verdict: 'unknown', wardUrl: W }), /아직 확인하지 못했습니다/);
    const offline = deniedPage({ verdict: 'unknown', reason: 'agent_offline', wardUrl: W });
    assert.match(offline, /이 PC 의 Ward 에이전트가 최근 3분간 서버에 보고하지 않았습니다/);
    assert.match(offline, /설치 탭에서 설치\(등록\)/);
    assert.match(offline, /1분쯤 기다리면/);
    assert.match(offline, /판정 코드: unknown \/ agent_offline/);
    // 사유는 unknown 일 때만 문구를 바꾼다
    assert.doesNotMatch(deniedPage({ verdict: 'noncompliant', reason: 'agent_offline', wardUrl: W }), /최근 3분간/);
  });

  test('rd·nonce 가 있을 때만 재시도 버튼과 스크립트, 주소는 이스케이프된 href 로만 들어간다', () => {
    const rd = 'https://note.datasee.co.kr/p?a=1&b="><script>alert(1)</script>';
    const html = deniedPage({ verdict: 'noncompliant', wardUrl: W, rd, nonce: 'N0nce+/=' });
    assert.match(html, /id="retry" href="https:\/\/note\.datasee\.co\.kr\/p\?a=1&amp;b=&quot;&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;">다시 시도</);
    assert.equal(html.split('<script').length - 1, 1, '스크립트는 우리 것 하나뿐');
    assert.match(html, /<script nonce="N0nce\+\/=">/);
    assert.match(html, /<style nonce="N0nce\+\/=">/);
    assert.ok(html.includes(`MAX=${DENIED_RETRY_MAX},left=${DENIED_RETRY_SEC}`));
    assert.equal(DENIED_RETRY_SEC, 20); assert.equal(DENIED_RETRY_MAX, 15);
    assert.match(html, /sessionStorage/);
    assert.match(html, /Ward 콘솔 열기/);
    // 외부 자원 없음: http(s) 주소는 재시도 href 와 ward 콘솔 링크뿐
    assert.doesNotMatch(html, /<link|<img|src=/);

    for (const h of [deniedPage({ verdict: 'noncompliant', wardUrl: W }), deniedPage({ verdict: 'noncompliant', wardUrl: W, nonce: 'n' }), deniedPage({ verdict: 'noncompliant', wardUrl: W, rd })]) {
      assert.doesNotMatch(h, /<script|id="retry"|다시 시도</);
      assert.match(h, /Ward 콘솔 열기/);
    }
  });

  test('CSP: nonce 로만 인라인 허용, 나머지는 전부 막는다', () => {
    const csp = deniedCsp('abc');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'nonce-abc'/);
    assert.match(csp, /style-src 'nonce-abc'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:/);
  });

  test('쿼리 v·r 허용 목록', () => {
    for (const v of ['noncompliant', 'unknown', 'no_device', 'error', 'app_access']) assert.equal(parseDeniedVerdict(v), v);
    for (const v of ['compliant', 'exempt', 'NONCOMPLIANT', '', ' unknown', '<script>', undefined, null, ['unknown'], 1]) assert.equal(parseDeniedVerdict(v), null);
    assert.equal(parseDeniedReason('agent_offline'), 'agent_offline');
    for (const r of ['other_reason', 'AGENT_OFFLINE', 'agent-offline', '', '<b>', undefined, ['agent_offline']]) assert.equal(parseDeniedReason(r), null);
  });
});
