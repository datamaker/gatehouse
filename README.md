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
| `GATEHOUSE_SESSION_TTL_HOURS` | 세션 수명 | `12` |
| `GATEHOUSE_ADMIN_EMAILS` | 로그인 시 admin 권한을 받을 이메일 (comma) | (없음) |
| `GATEHOUSE_REDIRECT_DOMAINS` | 로그인 후 rd 리다이렉트 허용 도메인 | cookie+allowed 도메인 |
| `DATABASE_URL` | Postgres | localhost:5435 |

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

## 관리 콘솔

`GATEHOUSE_ADMIN_EMAILS`에 등록된 이메일로 로그인하면 루트(`/`)에서 관리 콘솔이 열립니다:

- **사용자** — 활성/비활성 토글(비활성화 즉시 전체 앱에서 세션 무효화), admin 권한 부여, 세션 강제 종료
- **감사 로그** — 로그인/로그아웃/거부 이력, 이메일 필터

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
   ```
3. `docker compose up -d --build`
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
    proxy_pass http://app;
  }

  location @login {
    return 302 https://auth.datasee.co.kr/login?rd=https://$host$request_uri;
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
| `GET /auth/traefik` | forward-auth (Traefik, 200/302) |
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
