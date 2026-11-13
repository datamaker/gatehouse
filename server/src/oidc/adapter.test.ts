import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { GatehouseAdapter, revokeAccount } from './adapter.js';

// 메모리 저장소만 쓰는 부분이라 DB 가 필요 없다(Client 조회만 Postgres 를 본다).
const session = new GatehouseAdapter('Session');
const grant = new GatehouseAdapter('Grant');
const access = new GatehouseAdapter('AccessToken');
const code = new GatehouseAdapter('AuthorizationCode');
const device = new GatehouseAdapter('DeviceCode');
const interaction = new GatehouseAdapter('Interaction');

describe('revokeAccount', () => {
  test('그 계정의 OP 세션·grant·코드·토큰·interaction 만 지운다', async () => {
    await session.upsert('s1', { accountId: '1', uid: 'uid-s1' }, 3600);
    await session.upsert('s1b', { accountId: '1', uid: 'uid-s1b' }, 3600); // 다른 브라우저
    await session.upsert('s2', { accountId: '2', uid: 'uid-s2' }, 3600);
    await session.upsert('anon', { uid: 'uid-anon' }, 3600); // 로그인 전 세션
    await grant.upsert('g1', { accountId: '1', clientId: 'vault' }, 3600);
    await grant.upsert('g2', { accountId: '2', clientId: 'vault' }, 3600);
    await access.upsert('at1', { accountId: '1', grantId: 'g1' }, 3600);
    await access.upsert('at2', { accountId: '2', grantId: 'g2' }, 3600);
    await code.upsert('c1', { accountId: '1', grantId: 'g1' }, 60);
    await device.upsert('d1', { accountId: '1', grantId: 'g1', userCode: 'ABCD' }, 600);
    await device.upsert('d-pending', { userCode: 'WXYZ' }, 600); // 아직 아무도 승인하지 않은 코드
    await interaction.upsert('i1', { session: { accountId: '1' } }, 600);
    await interaction.upsert('i1b', { result: { login: { accountId: '1' } } }, 600);
    await interaction.upsert('i2', { session: { accountId: '2' } }, 600);

    assert.equal(revokeAccount('1'), 8);

    for (const [a, id] of [[session, 's1'], [session, 's1b'], [grant, 'g1'], [access, 'at1'], [code, 'c1'], [device, 'd1'], [interaction, 'i1'], [interaction, 'i1b']] as const) {
      assert.equal(await a.find(id), undefined, `${id} 는 지워져야 한다`);
    }
    assert.equal(await session.findByUid('uid-s1'), undefined);
    assert.equal(await device.findByUserCode('ABCD'), undefined);

    // 다른 계정·익명 상태는 그대로
    assert.ok(await session.find('s2'));
    assert.ok(await session.find('anon'));
    assert.ok(await grant.find('g2'));
    assert.ok(await access.find('at2'));
    assert.ok(await device.findByUserCode('WXYZ'));
    assert.ok(await interaction.find('i2'));
  });

  test('지울 것이 없으면 0, 두 번 불러도 안전', () => {
    assert.equal(revokeAccount('1'), 0);
    assert.equal(revokeAccount('no-such'), 0);
  });

  test('"1" 과 "10" 을 헷갈리지 않는다', async () => {
    await session.upsert('s10', { accountId: '10', uid: 'uid-s10' }, 3600);
    assert.equal(revokeAccount('1'), 0);
    assert.ok(await session.find('s10'));
    assert.equal(revokeAccount('10'), 1);
  });
});
