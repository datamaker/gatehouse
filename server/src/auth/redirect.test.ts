import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkRedirect } from './redirect.js';

const BASE = 'https://auth.datasee.co.kr';
const DOMAINS = ['datasee.co.kr'];
const rd = (v: string | undefined) => checkRedirect(v, BASE, DOMAINS);

describe('checkRedirect', () => {
  test('같은 origin 의 상대 경로는 통과(쿼리·해시 유지)', () => {
    assert.equal(rd('/'), '/');
    assert.equal(rd('/oidc-interaction/abc'), '/oidc-interaction/abc');
    assert.equal(rd('/a/b?x=1&y=%2F#frag'), '/a/b?x=1&y=%2F#frag');
  });

  test('브라우저가 다른 호스트로 읽는 상대 경로는 거절', () => {
    assert.equal(rd('//evil.example'), null);
    assert.equal(rd('//evil.example/path'), null);
    assert.equal(rd('/\\evil.example'), null); // 브라우저는 \ 를 / 로 읽는다
    assert.equal(rd('/\\/evil.example'), null);
    assert.equal(rd('\\\\evil.example'), null);
    assert.equal(rd('/\t/evil.example'), null); // 탭은 URL 파서가 지워서 //evil.example 이 된다
    assert.equal(rd('/\n/evil.example'), null);
    assert.equal(rd('/\r/evil.example'), null);
    assert.equal(rd('/ok\u0000'), null);
    assert.equal(rd('/ok\u007f'), null);
  });

  test('허용 도메인(및 서브도메인)의 절대 주소만 통과', () => {
    assert.equal(rd('https://vault.datasee.co.kr/x?y=1'), 'https://vault.datasee.co.kr/x?y=1');
    assert.equal(rd('https://datasee.co.kr/'), 'https://datasee.co.kr/');
    assert.equal(rd('https://VAULT.DATASEE.CO.KR/'), 'https://vault.datasee.co.kr/');
    assert.equal(rd('https://evil.example/'), null);
    assert.equal(rd('https://datasee.co.kr.evil.example/'), null);
    assert.equal(rd('https://evildatasee.co.kr/'), null);
    assert.equal(rd('https://datasee.co.kr@evil.example/'), null); // userinfo 로 속이기
    assert.equal(rd('https://evil.example\\@datasee.co.kr/'), null);
    assert.equal(rd('https://evil.example/?x=datasee.co.kr'), null);
  });

  test('http(s) 가 아닌 스킴·빈 값·형식 오류는 거절', () => {
    assert.equal(rd('javascript:alert(1)'), null);
    assert.equal(rd('data:text/html,x'), null);
    assert.equal(rd('ftp://vault.datasee.co.kr/'), null);
    assert.equal(rd(''), null);
    assert.equal(rd(undefined), null);
    assert.equal(rd('evil.example'), null);
    assert.equal(rd(' //evil.example'), null);
    assert.equal(checkRedirect(['/a', '/b'] as unknown as string, BASE, DOMAINS), null); // ?rd=a&rd=b
  });

  test('개발 환경(localhost base)에서도 같은 origin 만', () => {
    assert.equal(checkRedirect('/x', 'http://localhost:9100', []), '/x');
    assert.equal(checkRedirect('//localhost:9999/x', 'http://localhost:9100', []), null);
  });
});
