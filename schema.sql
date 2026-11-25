-- MINDLET schema.sql — 신규 빈 DB 전용입니다.
-- 이미 memos 테이블에 데이터가 있다면 이 파일 대신 migration.sql을 사용하세요.
-- Supabase SQL Editor에서 한 번에 실행합니다. 샘플 데이터는 넣지 않습니다.

create extension if not exists pgcrypto;

-- ───────────── 테이블 ─────────────

create table public.memos (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 80),
  content text not null check (char_length(content) between 1 and 2000),
  color text not null default '#fef3c7' check (char_length(color) > 0),
  position integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 작성자 암호 해시 (공개 테이블과 분리)
create table public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

-- 관리자 세션: 원본 토큰이 아닌 HMAC 검증값만 저장
create table public.admin_sessions (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- 요청 제한 카운터 (고정 윈도우)
create table public.rate_limits (
  key_hash text primary key,
  window_start timestamptz not null default now(),
  hits integer not null default 0
);

create index memos_created_at_idx on public.memos (created_at desc);
create index admin_sessions_expires_at_idx on public.admin_sessions (expires_at);
create index rate_limits_window_start_idx on public.rate_limits (window_start);

-- ───────────── 함수 (모두 SECURITY INVOKER, service_role 전용) ─────────────

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

-- 메모와 암호 해시를 한 트랜잭션으로 저장
create or replace function public.create_memo_with_credentials(
  p_title text,
  p_content text,
  p_password_hash text,
  p_color text default '#fef3c7'
)
returns public.memos
language plpgsql
set search_path = public
as $$
declare
  inserted_memo public.memos;
begin
  if char_length(btrim(p_title)) < 1 or char_length(p_title) > 80 then
    raise exception 'Invalid title length';
  end if;

  if char_length(btrim(p_content)) < 1 or char_length(p_content) > 2000 then
    raise exception 'Invalid content length';
  end if;

  if p_password_hash !~ '^\$2[aby]\$\d{2}\$.{53}$' then
    raise exception 'Invalid password hash';
  end if;

  insert into public.memos (title, content, color)
  values (p_title, p_content, coalesce(nullif(p_color, ''), '#fef3c7'))
  returning * into inserted_memo;

  insert into public.memo_credentials (memo_id, password_hash)
  values (inserted_memo.id, p_password_hash);

  return inserted_memo;
end;
$$;

-- 시도 1회를 기록하고 허용 여부를 반환 (원자적 upsert)
create or replace function public.consume_rate_limit(
  p_key_hash text,
  p_limit integer,
  p_window_seconds integer
)
returns boolean
language plpgsql
set search_path = public
as $$
declare
  current_hits integer;
  window_length interval := make_interval(secs => p_window_seconds);
begin
  insert into public.rate_limits as r (key_hash, window_start, hits)
  values (p_key_hash, now(), 1)
  on conflict (key_hash) do update
  set window_start = case
        when r.window_start <= now() - window_length then now()
        else r.window_start
      end,
      hits = case
        when r.window_start <= now() - window_length then 1
        else r.hits + 1
      end
  returning hits into current_hits;

  delete from public.rate_limits where window_start < now() - interval '1 day';

  return current_hits <= p_limit;
end;
$$;

-- 성공한 시도는 실패 카운터에서 되돌림
create or replace function public.release_rate_limit(p_key_hash text)
returns void
language sql
set search_path = public
as $$
  update public.rate_limits
  set hits = greatest(hits - 1, 0)
  where key_hash = p_key_hash;
$$;

-- ───────────── 권한 (RLS + GRANT 함께 관리) ─────────────

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

-- Supabase 기본 권한이 남지 않도록 이 앱의 테이블만 명시적으로 회수
revoke all on public.memos from public, anon, authenticated;
revoke all on public.memo_credentials from public, anon, authenticated;
revoke all on public.admin_sessions from public, anon, authenticated;
revoke all on public.rate_limits from public, anon, authenticated;

-- 공개 조회: 명시한 컬럼만
grant select (id, title, content, color, position, created_at, updated_at)
on public.memos to anon, authenticated;

grant all on public.memos to service_role;
grant all on public.memo_credentials to service_role;
grant all on public.admin_sessions to service_role;
grant all on public.rate_limits to service_role;

-- 정책: memos 조회만 허용. 나머지 테이블에는 일반 사용자 정책을 만들지 않음.
create policy "Public memos are readable"
on public.memos
for select
to anon, authenticated
using (true);

revoke all on function public.set_updated_at() from public, anon, authenticated;
revoke all on function public.create_memo_with_credentials(text, text, text, text) from public, anon, authenticated;
revoke all on function public.consume_rate_limit(text, integer, integer) from public, anon, authenticated;
revoke all on function public.release_rate_limit(text) from public, anon, authenticated;

grant execute on function public.create_memo_with_credentials(text, text, text, text) to service_role;
grant execute on function public.consume_rate_limit(text, integer, integer) to service_role;
grant execute on function public.release_rate_limit(text) to service_role;
