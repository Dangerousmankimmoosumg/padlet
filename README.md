# MINDLET

Next.js · Supabase · Vercel 기반의 단일 메모 보드입니다. 주소를 아는 사람은 누구나 메모를 보고 쓸 수 있고, 작성자는 자신이 정한 숫자 4자리 암호로, 관리자는 별도 로그인 후 메모를 삭제합니다.

## 로컬 실행

1. 압축을 푼 프로젝트 폴더를 엽니다.
2. `node -v`, `npm -v`로 버전을 확인합니다(강사 지정 버전, 없으면 Node.js 22 이상).
3. `npm ci`
4. `cp .env.example .env.local` 후 본인의 Supabase 값을 입력합니다.
   - `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`는 Supabase 대시보드 → Project Settings → API Keys에서 복사합니다.
5. 관리자 암호 해시 생성(원하는 암호로 교체):
   ```bash
   node -e "require('bcryptjs').hash(process.argv[1], 12).then(h => { console.log('원본(Vercel용):', h); console.log('.env.local용:', h.replace(/\\$/g, '\\\\$')); })" "원하는-관리자-암호"
   ```
   `.env.local`은 `$`를 변수 치환으로 해석하므로 **`.env.local`에는 `\$`로 이스케이프한 값**을, Vercel 화면에는 **원본 값**을 넣습니다.
6. 세션 비밀값 생성(32자 이상):
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
   ```
7. DB 초기화 — Supabase SQL Editor에서 하나만 실행합니다.
   - **신규 빈 DB:** `schema.sql`
   - **기존 데이터가 있는 DB:** `migration.sql` (파일 상단의 적용 전제조건과 [0단계] 확인 쿼리를 먼저 확인하고 백업 후 실행)
8. `npm run dev` → http://localhost:3000

환경 변수가 없거나 형식이 틀리면 서버 로그에 **변수 이름과 해결 방법만** 출력되고, 화면에는 일반 오류 메시지가 표시됩니다.

## Vercel 배포

1. 저장소를 Vercel에 연결(Import Project)합니다.
2. Project Settings → Environment Variables에 `.env.example`의 다섯 변수를 Production·Preview에 등록합니다. (`ADMIN_PASSWORD_HASH`는 이스케이프 없는 원본 해시)
3. Deploy 후 아래를 확인합니다: 빈 보드 표시 → + 버튼으로 작성 → 올바른/틀린 암호 삭제 → 관리자 로그인·삭제·전체 삭제·로그아웃.

비밀값(`SUPABASE_SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `ADMIN_SESSION_SECRET`)에는 `NEXT_PUBLIC_` 접두사를 붙이지 마세요. 레거시 `ANON_KEY`/`SERVICE_ROLE_KEY`는 사용하지 않습니다.

## 보안 구조

- 브라우저는 Publishable key로 공개 컬럼(`id,title,content,color,position,created_at,updated_at`)만 조회합니다.
- 작성·삭제·관리자 작업은 Node.js Runtime 서버 API가 `server-only` Secret key 클라이언트(세션 미저장)로 처리합니다.
- 암호 해시는 `memo_credentials`에 분리 저장되고, 메모+해시는 RPC 한 번(단일 트랜잭션)으로 저장됩니다. 삭제 시 서버에서 bcrypt로 비교합니다.
- RLS가 모든 앱 테이블에 켜져 있고, `anon`/`authenticated`는 `memos` 공개 컬럼 SELECT만 가능합니다. 나머지 테이블·RPC는 `service_role` 전용입니다(SQL에서 GRANT/REVOKE 명시).
- 관리자 세션: 무작위 토큰을 쿠키(HttpOnly, SameSite=Strict, Path=/, 프로덕션 Secure)로 전달하고, DB에는 `ADMIN_SESSION_SECRET` HMAC 검증값과 만료시간(8시간)만 저장합니다. 요청마다 서버에서 확인하며 로그아웃 시 폐기됩니다.
- 요청 제한은 Supabase의 `rate_limits` 테이블과 원자적 RPC로 구현되며 bcrypt 실행 전에 확인합니다(저장소 오류 시 작업 거부):
  작성 IP당 10분 20회 / 삭제 IP당 10분 30회 / 메모+IP별 삭제 실패 10분 5회 / 관리자 로그인 실패 IP당 15분 5회.
- 클라이언트 IP: Vercel은 `X-Forwarded-For`·`X-Real-IP`를 접속 IP로 덮어써 위조를 막습니다([공식 문서](https://vercel.com/docs/headers/request-headers)). 앱은 `x-real-ip` → `x-forwarded-for` 첫 값을 사용합니다. Vercel 밖(예: 로컬 `next start`)에서는 이 헤더를 신뢰할 수 없습니다.
- Origin 검사: 모든 상태 변경 API(POST/DELETE)는 `Origin` 헤더가 필수이며 요청 URL의 origin과 같아야 합니다. 허용 주소 환경 변수는 없고 로컬·Preview·Production에서 동일하게 동작합니다.

## API

| 경로 | 설명 |
| --- | --- |
| `GET /api/memos` | 메모 목록 |
| `POST /api/memos` | 메모 작성 |
| `POST /api/memos/delete`, `POST /api/memos/[id]/delete` | 작성자 암호 삭제 (동일 핸들러) |
| `POST /api/admin/login`, `/logout`, `GET /api/admin/session` | 관리자 인증 |
| `POST /api/admin/delete`, `DELETE\|POST /api/admin/memos/[id]` | 관리자 개별 삭제 (동일 핸들러) |
| `POST /api/admin/delete-all`, `DELETE\|POST /api/admin/memos` | 관리자 전체 삭제 (동일 핸들러) |

상태 코드: 400 잘못된 JSON·UUID·입력, 401 비인증, 403 Origin 불일치·암호 불일치, 429 요청 제한, 500 일반 오류.
