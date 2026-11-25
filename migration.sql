-- MINDLET migration.sql — 기존 DB(데이터가 있는 memos 테이블) 변경용입니다.
--
-- 적용 전제조건
--   1. 먼저 Supabase에서 백업(또는 Database > Backups)을 만들어 두세요.
--   2. 아래 [0단계] 확인 쿼리를 실행해 실제 구조를 확인하세요.
--      - public.memos 에 id(uuid), title, content 컬럼이 있어야 합니다.
--      - 기존 암호 해시는 memos.password_hash 에 bcrypt($2a/$2b/$2y)로 저장되어 있거나,
--        이미 memo_credentials 에 있어야 합니다. 평문 또는 다른 해시 방식이면 중단됩니다.
--   3. 구조가 다르면 이 파일을 그대로 실행하지 말고 먼저 맞게 수정하세요.
--   4. [1단계]는 한 트랜잭션입니다. 검증에 실패하면 예외가 발생하고 전체가 롤백됩니다.
--   5. 앱 배포 전에 실행해야 합니다(새 코드는 admin_sessions, rate_limits, RPC를 사용합니다).
--
-- 건드리지 않는 것: 이 앱 외의 테이블, public 스키마 전체 권한.

-- ═════════ [0단계] 읽기 전용 확인 (먼저 따로 실행) ═════════
--
-- select column_name, data_type, is_nullable, column_default
--   from information_schema.columns
--  where table_schema = 'public' and table_name = 'memos' order by ordinal_position;
--
-- select count(*) as memos,
--        count(*) filter (where password_hash is null) as no_hash,
--        count(*) filter (where password_hash !~ '^\$2[aby]\$') as non_bcrypt
--   from public.memos;            -- password_hash 컬럼이 있을 때만
--
-- select conname, pg_get_constraintdef(oid) from pg_constraint
--  where conrelid = 'public.memos'::regclass;
--
-- select policyname, cmd, roles from pg_policies
--  where schemaname = 'public' and tablename in ('memos','memo_credentials');
--
-- select grantee, privilege_type from information_schema.role_table_grants
--  where table_schema = 'public' and table_name in ('memos','memo_credentials');

-- ═════════ [1단계] 마이그레이션 ═════════

begin;

create extension if not exists pgcrypto;

-- 1) 누락된 컬럼 보강 (기존 값은 유지)
alter table public.memos add column if not exists color text;
alter table public.memos add column if not exists position integer;
alter table public.memos add column if not exists created_at timestamptz;
alter table public.memos add column if not exists updated_at timestamptz;

update public.memos set color = '#fef3c7' where color is null or color = '';
update public.memos set position = 0 where position is null;
update public.memos set created_at = now() where created_at is null;
update public.memos set updated_at = coalesce(updated_at, created_at);

alter table public.memos alter column color set default '#fef3c7';
alter table public.memos alter column color set not null;
alter table public.memos alter column position set default 0;
alter table public.memos alter column position set not null;
alter table public.memos alter column created_at set default now();
alter table public.memos alter column created_at set not null;
alter table public.memos alter column updated_at set default now();
alter table public.memos alter column updated_at set not null;

-- 새 행에만 길이 제약을 적용(NOT VALID): 기존 데이터는 삭제·변경하지 않습니다.
do $$
begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.memos'::regclass and conname = 'memos_title_length_check') then
    alter table public.memos add constraint memos_title_length_check
      check (char_length(title) between 1 and 80) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.memos'::regclass and conname = 'memos_content_length_check') then
    alter table public.memos add constraint memos_content_length_check
      check (char_length(content) between 1 and 2000) not valid;
  end if;
end $$;

-- 2) 비공개 테이블 생성
create table if not exists public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

create table if not exists public.admin_sessions (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create table if not exists public.rate_limits (
  key_hash text primary key,
  window_start timestamptz not null default now(),
  hits integer not null default 0
);

create index if not exists memos_created_at_idx on public.memos (created_at desc);
create index if not exists admin_sessions_expires_at_idx on public.admin_sessions (expires_at);
create index if not exists rate_limits_window_start_idx on public.rate_limits (window_start);

-- 3) 기존 해시 이전 → 검증 → 공개 테이블에서 제거
do $$
declare
  memo_count bigint;
  missing_count bigint;
  mismatch_count bigint;
  non_bcrypt_count bigint;
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos' and column_name = 'password_hash'
  ) then
    execute $q$
      select count(*) from public.memos
      where password_hash is not null and password_hash !~ '^\$2[aby]\$\d{2}\$.{53}$'
    $q$ into non_bcrypt_count;
    if non_bcrypt_count > 0 then
      raise exception 'bcrypt가 아닌 password_hash가 % 건 있습니다. 마이그레이션을 중단합니다.', non_bcrypt_count;
    end if;

    execute $q$
      insert into public.memo_credentials (memo_id, password_hash)
      select id, password_hash from public.memos where password_hash is not null
      on conflict (memo_id) do nothing
    $q$;

    execute $q$
      select count(*) from public.memos m
      where m.password_hash is not null
        and not exists (select 1 from public.memo_credentials c where c.memo_id = m.id)
    $q$ into missing_count;
    if missing_count > 0 then
      raise exception '이전되지 않은 해시가 % 건 있습니다.', missing_count;
    end if;

    execute $q$
      select count(*) from public.memos m
      join public.memo_credentials c on c.memo_id = m.id
      where m.password_hash is not null and c.password_hash <> m.password_hash
    $q$ into mismatch_count;
    if mismatch_count > 0 then
      raise exception '기존 memo_credentials 와 다른 해시가 % 건 있습니다. 수동 확인이 필요합니다.', mismatch_count;
    end if;

    -- NOT NULL 등 기존 제약과 함께 컬럼이 사라져 충돌이 해소됩니다.
    execute 'alter table public.memos drop column password_hash';
  end if;

  -- 해시가 없는 메모는 작성자가 삭제할 수 없으므로 경고만 남깁니다(관리자 삭제는 가능).
  select count(*) into memo_count from public.memos;
  select count(*) into missing_count from public.memos m
   where not exists (select 1 from public.memo_credentials c where c.memo_id = m.id);
  raise notice 'memos=%, 암호 해시 없는 메모=%', memo_count, missing_count;
end $$;

-- 4) updated_at 트리거와 함수
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

drop trigger if exists memos_set_updated_at on public.memos;
create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

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

create or replace function public.release_rate_limit(p_key_hash text)
returns void
language sql
set search_path = public
as $$
  update public.rate_limits
  set hits = greatest(hits - 1, 0)
  where key_hash = p_key_hash;
$$;

-- 5) RLS: 이 앱의 테이블에서 기존 정책을 모두 제거하고 필요한 것만 다시 생성
do $$
declare
  pol record;
begin
  for pol in
    select schemaname, tablename, policyname from pg_policies
    where schemaname = 'public'
      and tablename in ('memos', 'memo_credentials', 'admin_sessions', 'rate_limits')
  loop
    execute format('drop policy %I on %I.%I', pol.policyname, pol.schemaname, pol.tablename);
  end loop;
end $$;

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

-- 6) GRANT: 기존 권한(컬럼 권한 포함)을 회수한 뒤 필요한 권한만 부여
revoke all on public.memos from public, anon, authenticated;
revoke all on public.memo_credentials from public, anon, authenticated;
revoke all on public.admin_sessions from public, anon, authenticated;
revoke all on public.rate_limits from public, anon, authenticated;

grant select (id, title, content, color, position, created_at, updated_at)
on public.memos to anon, authenticated;

grant all on public.memos to service_role;
grant all on public.memo_credentials to service_role;
grant all on public.admin_sessions to service_role;
grant all on public.rate_limits to service_role;

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

commit;

-- ═════════ [2단계] 적용 후 확인 (읽기 전용) ═════════
--
-- select count(*) from public.memos;                                 -- 마이그레이션 전과 동일해야 함
-- select count(*) from public.memo_credentials;                       -- 해시가 있던 메모 수와 동일해야 함
-- select column_name from information_schema.columns
--  where table_schema='public' and table_name='memos' and column_name='password_hash';  -- 0행이어야 함
-- select tablename, rowsecurity from pg_tables
--  where schemaname='public' and tablename in ('memos','memo_credentials','admin_sessions','rate_limits');
-- select grantee, table_name, privilege_type from information_schema.role_table_grants
--  where table_schema='public' and grantee in ('anon','authenticated')
--    and table_name in ('memo_credentials','admin_sessions','rate_limits');   -- 0행이어야 함
-- select policyname, tablename, cmd, roles from pg_policies where schemaname='public';
