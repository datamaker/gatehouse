/**
 * 로그인 뒤 돌아갈 주소(`rd`) 검증. 오픈 리다이렉트를 막는다.
 *
 * 설정을 인자로 받아 config.ts 없이도 테스트할 수 있게 했다.
 * - 상대 경로는 문자열 모양이 아니라 브라우저와 같은 방식(URL 파서)으로 풀어 본 뒤 같은 origin 인지 본다.
 *   `/\evil.example` 이나 `/<TAB>/host` 는 문자열로는 `/` 로 시작하지만 브라우저는 `//host` 로 읽는다.
 * - 역슬래시와 제어 문자는 이유를 따지지 않고 거절한다(정상 주소에는 나오지 않는다).
 * - 절대 주소는 http(s) 이고 허용 도메인(및 그 서브도메인)일 때만.
 */
// eslint-disable-next-line no-control-regex
const FORBIDDEN = /[\u0000-\u001f\u007f\\]/;

export function checkRedirect(
  rd: string | undefined | null,
  base: string,
  allowedDomains: string[],
): string | null {
  if (!rd || typeof rd !== 'string') return null;
  if (FORBIDDEN.test(rd)) return null;

  if (rd.startsWith('/')) {
    let url: URL;
    let origin: string;
    try {
      origin = new URL(base).origin;
      url = new URL(rd, base);
    } catch {
      return null;
    }
    if (url.origin !== origin) return null; // `//host/…` 는 여기서 걸린다
    return url.pathname + url.search + url.hash;
  }

  let url: URL;
  try {
    url = new URL(rd);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const host = url.hostname.toLowerCase();
  const ok = allowedDomains.some((d) => host === d || host.endsWith(`.${d}`));
  return ok ? url.href : null;
}
