# gatehouse

사내 로그인 게이트웨이. **Google Workspace 로그인만** 허용하고(패스워드 없음),
허용된 도메인(`datasee.co.kr`) 구성원은 가입 절차 없이 자동으로
로그인됩니다. nginx/Traefik forward-auth로 어떤 내부 앱이든 코드 수정 없이 보호할 수 있습니다.

## 동작 방식

```
사용자 ──▶ app.datasee.co.kr (nginx/Traefik)
              │  forward-auth 서브요청
              ▼
        gatehouse /auth/verify ── 세션 OK → 200 + X-Auth-Email 헤더 → 앱 통과
              │  세션 없음
              ▼
        /login → Google OAuth (PKCE) → hd 클레임 검증 → 세션 쿠키 발급 → 원래 URL로 복귀
```

- 개인 Gmail(`hd` 클레임 없음)과 허용 외 도메인은 403으로 거부됩니다.
- 첫 로그인 시 사용자 레코드가 자동 생성됩니다(JIT provisioning).
- 모든 로그인/거부/로그아웃은 `login_events`에 감사 기록됩니다.
- 세션 쿠키는 `GATEHOUSE_COOKIE_DOMAIN`(예: `datasee.co.kr`) 전체 서브도메인에서 공유됩니다.
- 세션은 sliding 방식입니다: 활동이 있으면 유휴 만료(기본 24h)가 밀리고, 로그인 뒤 절대 상한(기본 7일)이 지나면 끝납니다.
  평일에 매일 쓰면 주 1회 로그인이 됩니다. **퇴사·분실 처리는 콘솔에서 사용자 비활성화**(세션 즉시 삭제) — Google 계정만 끊어서는 남은 세션이 상한까지 살아 있습니다.

## 설정

### 1. Google OAuth 클라이언트

[Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials)에서:

1. OAuth client ID 생성 (Web application)
2. Authorized redirect URI에 `https://auth.datasee.co.kr/callback` 추가
   (로컬 개발용으로 `http://localhost:9100/callback`도 추가)

### 2. 환경 변수

| 변수 | 설명 | 기본값 |
|---|---|---|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth 클라이언트 | (필수) |
| `GATEHOUSE_PUBLIC_URL` | gatehouse 공개 URL, 예: `https://auth.datasee.co.kr` | `http://localhost:9100` |
| `GATEHOUSE_ALLOWED_DOMAINS` | 허용할 Workspace 도메인 (comma) | `datasee.co.kr` |
| `GATEHOUSE_COOKIE_DOMAIN` | 세션 쿠키 도메인, 예: `datasee.co.kr` | (host-only) |
| `GATEHOUSE_COOKIE_SECRET` | state 쿠키 서명 시크릿 | https에서 필수 |
| `GATEHOUSE_SESSION_IDLE_HOURS` | 세션 유휴 만료(활동마다 연장) | `24` |
| `GATEHOUSE_SESSION_MAX_HOURS` | 세션 절대 상한(로그인 기준) | `168` |
| `GATEHOUSE_SESSION_TOUCH_MINUTES` | 활동 기록(연장) 최소 간격 | `10` |
| `GATEHOUSE_ADMIN_EMAILS` | 로그인 시 admin 권한을 받을 이메일 (comma) | (없음) |
| `GATEHOUSE_REDIRECT_DOMAINS` | 로그인 후 rd 리다이렉트 허용 도메인 | cookie+allowed 도메인 |
| `DATABASE_URL` | Postgres | localhost:5435 |
| `GATEHOUSE_ZT_MODE` | 제로트러스트 모드 `off` / `monitor`(기록만) / `enforce`(차단) | `off` |
| `GATEHOUSE_WARD_URL` | ward 콘솔 서버(서버 간 조회) | `http://ward:9600` |
| `GATEHOUSE_WARD_SECRET` | ward 의 `WARD_ZT_SECRET` 과 같은 값 | (ZT 켜면 필수) |
| `GATEHOUSE_WARD_PUBLIC_URL` | 거부 페이지에 보여 줄 ward 콘솔 주소 | `https://ward.datasee.co.kr` |
| `GATEHOUSE_ZT_FAIL_OPEN` | ward 장애 시 통과(`true`) / 차단(`false`) | `true` |
| `GATEHOUSE_ZT_CACHE_SEC` | 사용자+IP 별 판정 캐시 | `60` |
| `GATEHOUSE_ZT_TIMEOUT_MS` | ward 조회 타임아웃 | `1000` |
| `GATEHOUSE_ZT_EXEMPT_EMAILS` | 판정 면제 이메일 (comma) | (없음) |
| `GATEHOUSE_ZT_EXEMPT_HOSTS` | 판정 면제 앱 호스트 (comma, `*.` 와일드카드 가능) | (없음) |
| `GATEHOUSE_ZT_SOFT_HOSTS` | "막지 않고 제한"할 앱 호스트 (comma, `*.` 와일드카드 가능). `enforce` 에서 거부될 판정이어도 200 + `X-Auth-Device-Restricted: 1`. 면제가 아니라 판정·기록은 그대로 | (없음) |
| `GATEHOUSE_ZT_ENFORCE_EMAILS` | 전역 모드가 `monitor` 여도 `enforce` 를 적용할 사용자 (comma, 대소문자 무시). 전역 `off` 면 효과 없음 | (없음) |
| `GATEHOUSE_ZT_OIDC_EXEMPT_CLIENTS` | OIDC 로그인 단계에서 기기 판정으로 막지 않을 client_id (comma). device grant 클라이언트는 자동 제외 | (없음) |
| `GATEHOUSE_INTERNAL_SECRET` | `GET /internal/account`(계정 상태 조회) 공유 시크릿. 비어 있으면 라우트가 없다(404) | (없음) |

### 3. 실행

```bash
# 개발
docker compose -f docker-compose.dev.yml up -d   # postgres만
npm install
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... npm run dev
npm run dev:web   # 콘솔 개발 시 (localhost:5181, /api는 9100으로 프록시)

# 프로덕션
docker compose up -d
```

## 제로트러스트 (ward 디바이스 상태 판정)

forward-auth 판정에 "사람"뿐 아니라 "기기 상태"를 넣는다. ward(엔드포인트 보안, `~/datamaker/ward`)의 에이전트가 PC 마다
보안 상태(디스크 암호화·화면 잠금·방화벽·SIP·백신)를 보고하고, gatehouse 는 `/auth/verify` 때 ward 에
`GET /api/zt/posture?email=&ip=` 로 물어 **그 사용자의 기기 중 지금 접속한 IP 와 같은 기기**의 상태를 받는다.

- 브라우저↔기기 바인딩은 "에이전트가 보고한 IP = 요청 IP"다(사무실·OpenTunnel VPN 전제). NAT 뒤에서 여러 사람이 한 IP 를 쓰면
  같은 IP 의 다른 사람 기기와는 맞지 않지만(이메일로 먼저 좁힌다), 같은 사람이 등록 기기와 미등록 기기를 같은 NAT 뒤에서 쓰면 구분하지 못한다.
  이게 1차의 한계고, 2차는 Ward 앱의 로컬 증명(브라우저 → 127.0.0.1 → 서명된 증명)으로 간다.
- 모드: `monitor` 는 판정을 `zt_checks` 에 기록만 하고 통과시킨다(먼저 이걸로 한두 주 돌려 거부될 사람을 본다). `enforce` 는 `compliant` 일 때만 200,
  그 외(`noncompliant`, `unknown`, `no_device`)는 403. ward 가 안 닿거나 1초를 넘기면 `GATEHOUSE_ZT_FAIL_OPEN` 대로.
- forward-auth 는 요청마다 불리지만 사용자+IP 로 60초 캐시하므로 ward 는 분당 1회만 맞고, 기록도 그때 1건만 남는다.
- 앱에는 `X-Auth-Device`(ward 디바이스 id)·`X-Auth-Device-Status`·`X-Auth-Device-Restricted`(`0`/`1`) 헤더가 추가로 간다.
- 거부(403) 응답에는 `X-Auth-Denied: <noncompliant|unknown|no_device|error|app_access>` 와, ward 가 사유를 줬으면
  `X-Auth-Denied-Reason: <reason>`(지금은 `agent_offline` — 에이전트가 최근 3분간 보고하지 않음)이 붙는다. 사유는 `^[a-z_]{1,40}$` 만 받고 `zt_checks.reason` 에도 남는다.
- 제한 접근(소프트 호스트): `GATEHOUSE_ZT_SOFT_HOSTS` 의 앱은 실효 모드가 `enforce` 이고 판정이 거부여도 `/auth/verify` 가 200 을 주고
  `X-Auth-Device-Restricted: 1` 을 싣는다(`X-Auth-Device-Status` 는 실제 판정 그대로). 미준수 사용자가 ward 콘솔에서 무엇을 고쳐야 하는지는
  볼 수 있어야 하기 때문이고, 그 세션이 할 수 있는 일을 줄이는 것은 앱의 몫이다. 기록은 `allowed = true`, `restricted = true` 로 남고
  콘솔에 "제한 접근"으로 보인다. 면제 호스트·면제 이메일이 소프트 호스트보다 우선하고, 앱 접근 정책 거부는 소프트 호스트여도 그대로 403 이다.
  nginx 는 `auth_request_set` 으로 받은 값을 `proxy_set_header X-Auth-Device-Restricted` 로 **항상** 덮어써야 한다(클라이언트가 보낸 값이 앱에 닿지 않게).
- 선택 사용자만 차단: 전역은 `monitor` 로 둔 채 `GATEHOUSE_ZT_ENFORCE_EMAILS` 에 넣은 사용자에게만 `enforce` 를 적용한다
  (`zt_checks.mode` 에는 그 사용자에게 실제로 적용된 모드가 남는다). 면제(`EXEMPT_*`)가 이 목록보다 우선하고, fail-open 설정은 그대로 따른다.
- OIDC 로그인: 실효 모드가 `enforce` 인 사용자는 `authorization_code` 웹 클라이언트 로그인도 막는다(거부 안내 페이지, 코드 미발급).
  device grant 를 쓰는 클라이언트(CLI·VPN·에이전트)는 승인하는 브라우저와 기기의 IP 가 달라 막지 않고 기록만 하며,
  `GATEHOUSE_ZT_OIDC_EXEMPT_CLIENTS` 로 클라이언트를 더 뺄 수 있다. 그 외에는 지금처럼 기록만 한다.
- 거부 안내: 앱 nginx 에 `error_page 403 = @zt_denied;` 와 `deploy/snippets/zt-denied.conf` 의 named location 을 넣으면
  `/auth/denied?rd=<원래 주소>&v=<X-Auth-Denied 값>&r=<X-Auth-Denied-Reason 값>` 이 사유(기기 없음·미준수·미확인·에이전트 오프라인·ward 오류)와
  조치 방법을 보여 준다. 인증 호스트는 공인 인터넷으로 들어와 요청 IP 가 VPN IP 와 다르므로 이 페이지는 기기 판정을 다시 하지 않고,
  nginx 가 넘긴 `v`·`r`(허용 목록 밖의 값은 무시)만 쓴다. "다시 시도" 버튼과 20초마다의 자동 재시도(최대 15회)가 `rd` 로 돌아가 다시 판정받는다.
- 관리 콘솔 "제로트러스트" 탭에서 판정 기록(이메일·앱·IP·기기·판정)과 현재 설정을 본다. 설정은 env 로만 바꾼다.

테스트: `npm test` — 가짜 ward 서버로 off/monitor/enforce × 준수/미준수/기기없음/장애(fail-open·closed)/타임아웃/캐시/면제/사용자별 enforce 를 검증한다.

## 회수 전파 · 앱 접근 정책

- **로그아웃**: `GET /logout` 은 확인 페이지만 보여 주고(링크·이미지 한 번으로 로그아웃시키는 CSRF 방지), 그 페이지의 `POST /logout` 이 실제로 끊는다.
  `?rd=` 는 로그인과 같은 검증(같은 origin 상대 경로 또는 허용 도메인)을 거친다.
- **OIDC 세션**: 로그아웃·관리자 "세션 종료"·비활성화는 gatehouse 세션뿐 아니라 그 계정의 OP 세션·grant·코드·토큰도 지운다.
  OP 세션 수명은 유휴 만료(`GATEHOUSE_SESSION_IDLE_HOURS`)를 넘지 않고, authorization·device 요청마다 그 브라우저의 gatehouse 세션이
  살아 있고 같은 계정인지 확인한다(아니면 gatehouse 로그인으로 보낸다).
- **계정 상태 조회**: 자체 세션·토큰을 가진 앱은 `GET /internal/account?email=` (헤더 `X-Gatehouse-Secret`)로 묻는다.
  `200 {"email","active","revoked_before"}` / 모르는 이메일 `404 {"active":false}` / 시크릿 불일치 `401`.
  `revoked_before` 는 관리자 세션 종료·비활성화 때 now() 로 갱신되며, 그 이전에 발급된 세션·토큰은 무효로 취급해야 한다.
- **앱 접근 정책**: 콘솔 "앱 접근" 탭에서 앱(forward-auth 호스트 또는 `oidc:<client_id>`)을 `제한` 으로 바꾸면 허용 목록의 사용자만 통과한다.
  정책이 없거나 `전체 허용` 이면 활성 사용자 전원(기본). forward-auth 는 `403` + `X-Auth-Denied: app_access`, OIDC 는 코드 대신 거부 안내 페이지.
  `/auth/denied` 는 앱 접근 거부와 기기 거부를 다른 문구로 안내한다. 판정은 30초 캐시하고 관리자 변경 시 바로 비운다.
- **기기 로그인(device flow) 승인 화면**: 요청한 앱·IP·user-agent·시각을 보여 주고 직접 승인해야 한다(`?user_code=` 로 열어도 자동 승인되지 않는다).

## 관리 콘솔

`GATEHOUSE_ADMIN_EMAILS`에 등록된 이메일로 로그인하면 루트(`/`)에서 관리 콘솔이 열립니다:

- **사용자** — 활성/비활성 토글(비활성화 즉시 전체 앱에서 세션 무효화), admin 권한 부여, 세션 강제 종료
- **앱 접근** — 앱별 전체 허용/제한 전환, 허용 사용자 추가·제거
- **감사 로그** — 로그인/로그아웃/거부 이력(이메일 필터)과 관리자 작업 이력(사용자·세션·OIDC 클라이언트·앱 정책 변경, 시크릿은 기록하지 않음)
- **제로트러스트** — ward 기기 상태 판정 기록과 현재 모드·면제·사용자별 차단 목록(읽기 전용)

일반 사용자는 자신의 프로필만 보입니다. 자기 자신을 비활성화하거나 강등하는 건 막혀 있습니다(락아웃 방지).

## EC2 배포

1. EC2에 docker + compose 설치, 이 레포 클론
2. `.env` 작성:
   ```bash
   GATEHOUSE_PUBLIC_URL=https://auth.datasee.co.kr
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   GATEHOUSE_COOKIE_DOMAIN=datasee.co.kr
   GATEHOUSE_COOKIE_SECRET=$(openssl rand -base64 32)
   GATEHOUSE_ADMIN_EMAILS=datamaker@datasee.co.kr
   POSTGRES_PASSWORD=$(openssl rand -hex 16)
   # 항상 tls 오버레이까지 포함(nginx + gatehouse↔ward 네트워크). 이게 없으면 `docker compose up gatehouse` 가
   # 기본 파일만 읽어 ward_default 없이 재생성되고, 제로트러스트 조회가 매번 1초 타임아웃 → 모든 SSO 앱 API 가 1초 느려진다(2026-11-05 사건).
   COMPOSE_FILE=docker-compose.yml:docker-compose.tls.yml
   ```
3. `docker compose up -d --build`
   (`COMPOSE_FILE` 덕에 `-f` 를 매번 안 붙여도 된다. 배포 뒤 `docker inspect gatehouse-gatehouse-1 --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'` 에 `ward_default` 가 보여야 한다)
4. 앞단 TLS 종료(nginx/Caddy/ALB)에서 `auth.datasee.co.kr` → `localhost:9100` 프록시.
   `X-Forwarded-For`/`X-Forwarded-Proto` 전달 필수 (`trustProxy` 사용 중)
5. 보안그룹에서 9100 포트는 외부 차단, 프록시 경유만 허용

## 앱 보호하기

### nginx (`auth_request`)

```nginx
server {
  server_name app.datasee.co.kr;

  location = /_gatehouse/verify {
    internal;
    proxy_pass http://gatehouse:9100/auth/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
  }

  location / {
    auth_request /_gatehouse/verify;
    auth_request_set $auth_email $upstream_http_x_auth_email;
    proxy_set_header X-Auth-Email $auth_email;
    error_page 401 = @login;
    error_page 403 = @zt_denied;   # 제로트러스트 거부 → 안내 페이지 (deploy/snippets/zt-denied.conf)
    proxy_pass http://app;
  }

  location @login {
    return 302 https://auth.datasee.co.kr/login?rd=https://$host$request_uri;
  }

  location @zt_denied {
    return 302 https://auth.datasee.co.kr/auth/denied?rd=https://$host$request_uri;
  }
}
```

### Traefik (forwardAuth)

```yaml
http:
  middlewares:
    gatehouse:
      forwardAuth:
        address: http://gatehouse:9100/auth/traefik
        authResponseHeaders: [X-Auth-User, X-Auth-Email, X-Auth-Name]
```

앱에는 `X-Auth-Email` / `X-Auth-User` / `X-Auth-Name` 헤더가 전달됩니다.
**앱은 반드시 프록시 뒤에서만 접근 가능해야 합니다** (헤더 스푸핑 방지).

## 엔드포인트

| 경로 | 설명 |
|---|---|
| `GET /login?rd=` | Google 로그인 시작 |
| `GET /callback` | OAuth 콜백 |
| `GET\|POST /logout` | 세션 종료 |
| `GET /auth/verify` | forward-auth (nginx, 200/401) |
| `GET /auth/traefik` | forward-auth (Traefik, 200/302/403) |
| `GET /auth/denied?rd=` | 제로트러스트 거부 안내(HTML, 준수로 바뀌면 rd 로 복귀) |
| `GET /api/me` | 현재 사용자 JSON |
| `GET /healthz` | 헬스체크 |

## OIDC Provider (Phase 2)

gatehouse는 사내 앱들의 OIDC IdP이기도 합니다. forward-auth가 안 되는 경우
(다른 도메인의 앱, 네이티브 로그인 통합)에 사용하세요.

- **issuer**: `https://auth.datasee.co.kr/oidc`
- **discovery**: `{issuer}/.well-known/openid-configuration`
- **flow**: authorization code + PKCE(필수), `client_secret_post`
- **scopes**: `openid email profile` — email/name/picture는 id_token과 userinfo 양쪽에 포함
- **sub**: gatehouse users.id (문자열)

클라이언트 등록은 관리 콘솔 → "OIDC 클라이언트" 탭. secret은 생성 시 한 번만 표시됩니다.
로그인/동의 화면은 없습니다 — gatehouse 세션이 있으면 리다이렉트만으로 완료되고,
없으면 Google 로그인을 거쳐 자동 복귀합니다.

토큰·코드·grant는 메모리 저장이라 서버 재시작 시 무효화됩니다(서명키는 DB 영속).
앱은 자체 세션을 만들므로 재시작 영향은 "다음 로그인 때 리다이렉트 한 번" 수준입니다.

## 알려진 제약 (Phase 1)

- 세션 쿠키는 **하나의 등록 도메인**(cookie domain)만 커버합니다. 현재는
  `*.datasee.co.kr` 아래 앱만 보호 대상이라 문제 없고, 다른 도메인의 앱까지
  묶으려면 Phase 2의 OIDC provider가 필요합니다.
- 사용자 비활성화는 아직 SQL로 직접: `UPDATE users SET is_active = false WHERE email = '...'`

## 로드맵

- **Phase 2** — downstream OIDC provider (`node-oidc-provider`): 앱이 직접 OIDC 클라이언트로 연동
- **Phase 3** — device flow (opentunnel VPN 클라이언트 로그인)
- **Phase 4** — admin UI (사용자/그룹/클라이언트/감사 로그), 앱별 접근 정책
