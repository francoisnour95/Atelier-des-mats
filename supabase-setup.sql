-- Atelier des Mâts · cloud sync with a nickname + PIN (no email)
-- Paste this whole file into Supabase → SQL Editor → New query → Run.
-- Safe to run again: it replaces the functions and keeps existing data.
--
-- How it works
--   * Nicknames and PINs live in our own table. PINs are stored hashed (bcrypt), never as typed.
--   * After 5 wrong PINs an account is locked for 15 minutes.
--   * Signing in returns a random session token. The app keeps it on the device and sends it with each call.
--   * The tables are closed to the public API. The app can only use the functions below.
--   * Sharing: a signed-in user turns one scene into a link. The link holds a frozen copy of the scene
--     and works for 14 days. Anyone with the link can open it; keeping a copy needs an ID.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.am_users (
  id           uuid primary key default gen_random_uuid(),
  username     text not null unique check (username ~ '^[a-z0-9_.-]{3,20}$'),
  pin_hash     text not null,
  failed       int  not null default 0,
  locked_until timestamptz,
  created_at   timestamptz not null default now()
);

create table if not exists public.am_sessions (
  token_hash text primary key,
  user_id    uuid not null references public.am_users(id) on delete cascade,
  created_at timestamptz not null default now(),
  last_used  timestamptz not null default now()
);

create table if not exists public.am_library (
  user_id    uuid primary key references public.am_users(id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  rev        int   not null default 0,
  updated_at timestamptz not null default now()
);

-- Closed to direct access: row level security on, and no policies.
alter table public.am_users    enable row level security;
alter table public.am_sessions enable row level security;
alter table public.am_library  enable row level security;
revoke all on public.am_users, public.am_sessions, public.am_library from anon, authenticated;

-- ---------- helpers ----------
create or replace function public.am_new_session(p_user uuid)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare t text;
begin
  t := encode(gen_random_bytes(24), 'hex');
  insert into am_sessions(token_hash, user_id) values (encode(digest(t, 'sha256'), 'hex'), p_user);
  return t;
end $$;

create or replace function public.am_uid(p_token text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare u uuid;
begin
  update am_sessions set last_used = now()
   where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
   returning user_id into u;
  return u;
end $$;

-- ---------- create an ID ----------
create or replace function public.am_register(p_username text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uname text := lower(trim(p_username)); uid uuid;
begin
  if uname !~ '^[a-z0-9_.-]{3,20}$' then return json_build_object('error', 'bad_username'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return json_build_object('error', 'bad_pin'); end if;
  if exists (select 1 from am_users where username = uname) then return json_build_object('error', 'taken'); end if;
  insert into am_users(username, pin_hash) values (uname, crypt(p_pin, gen_salt('bf', 8))) returning id into uid;
  insert into am_library(user_id) values (uid);
  return json_build_object('token', am_new_session(uid), 'username', uname);
end $$;

-- ---------- sign in ----------
create or replace function public.am_login(p_username text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uname text := lower(trim(p_username)); u am_users;
begin
  select * into u from am_users where username = uname;
  if not found then
    perform crypt('0000', gen_salt('bf', 8));        -- same work as a real check, so timing gives nothing away
    return json_build_object('error', 'wrong');
  end if;
  if u.locked_until is not null and u.locked_until > now() then
    return json_build_object('error', 'locked', 'until', u.locked_until);
  end if;
  if crypt(coalesce(p_pin, ''), u.pin_hash) = u.pin_hash then
    update am_users set failed = 0, locked_until = null where id = u.id;
    return json_build_object('token', am_new_session(u.id), 'username', u.username);
  end if;
  if u.failed + 1 >= 5 then
    update am_users set failed = 0, locked_until = now() + interval '15 minutes' where id = u.id;
    return json_build_object('error', 'locked', 'until', now() + interval '15 minutes');
  end if;
  update am_users set failed = failed + 1 where id = u.id;
  return json_build_object('error', 'wrong', 'left', 5 - (u.failed + 1));
end $$;

create or replace function public.am_logout(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from am_sessions where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  return json_build_object('ok', true);
end $$;

-- ---------- the saved scenes ----------
create or replace function public.am_load(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := am_uid(p_token); r am_library;
begin
  if uid is null then return json_build_object('error', 'signed_out'); end if;
  select * into r from am_library where user_id = uid;
  return json_build_object('data', r.data, 'rev', r.rev, 'updated_at', r.updated_at);
end $$;

-- p_base_rev is the revision the device last saw. If someone else saved since, nothing is written
-- and the newer copy comes back, so the app can merge and try again.
create or replace function public.am_save(p_token text, p_data jsonb, p_base_rev int)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := am_uid(p_token); r am_library;
begin
  if uid is null then return json_build_object('error', 'signed_out'); end if;
  if octet_length(p_data::text) > 3000000 then return json_build_object('error', 'too_big'); end if;
  select * into r from am_library where user_id = uid for update;
  if p_base_rev is distinct from r.rev then
    return json_build_object('conflict', true, 'data', r.data, 'rev', r.rev);
  end if;
  update am_library set data = p_data, rev = rev + 1, updated_at = now() where user_id = uid returning * into r;
  return json_build_object('rev', r.rev, 'updated_at', r.updated_at);
end $$;

-- ---------- share a scene by link ----------
create table if not exists public.am_shares (
  code       text primary key,
  owner      uuid not null references public.am_users(id) on delete cascade,
  name       text not null,
  data       jsonb not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz
);
create index if not exists am_shares_owner on public.am_shares(owner, created_at);
alter table public.am_shares enable row level security;
revoke all on public.am_shares from anon, authenticated;

-- p_data is one scene ({lines, brelages, ficelles, ...}). Returns the code that goes in the link.
create or replace function public.am_share_create(p_token text, p_name text, p_data jsonb)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := am_uid(p_token); c text; abc text := '23456789abcdefghjkmnpqrstuvwxyz'; b bytea; i int;
        exp timestamptz := now() + interval '14 days';
begin
  if uid is null then return json_build_object('error', 'signed_out'); end if;
  if p_data is null or jsonb_typeof(p_data -> 'lines') is distinct from 'array' then return json_build_object('error', 'bad_scene'); end if;
  if octet_length(p_data::text) > 1000000 then return json_build_object('error', 'too_big'); end if;
  if (select count(*) from am_shares where owner = uid and created_at > now() - interval '1 hour') >= 30 then
    return json_build_object('error', 'too_many');
  end if;
  delete from am_shares where expires_at < now() - interval '30 days';     -- tidy up old links
  loop
    b := gen_random_bytes(10); c := '';
    for i in 0..9 loop c := c || substr(abc, 1 + get_byte(b, i) % length(abc), 1); end loop;
    exit when not exists (select 1 from am_shares where code = c);
  end loop;
  insert into am_shares(code, owner, name, data, expires_at)
       values (c, uid, left(coalesce(nullif(trim(p_name), ''), 'Scene'), 40), p_data, exp);
  return json_build_object('code', c, 'expires_at', exp);
end $$;

-- Open a link. No ID needed.
create or replace function public.am_share_get(p_code text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare s am_shares; who text;
begin
  select * into s from am_shares where code = lower(trim(coalesce(p_code, '')));
  if not found then return json_build_object('error', 'not_found'); end if;
  if s.expires_at is not null and s.expires_at < now() then return json_build_object('error', 'expired'); end if;
  select username into who from am_users where id = s.owner;
  return json_build_object('name', s.name, 'data', s.data, 'from', who, 'created_at', s.created_at, 'expires_at', s.expires_at);
end $$;

-- Only these functions are callable from the app.
revoke all on function public.am_new_session(uuid), public.am_uid(text) from public, anon, authenticated;
grant execute on function public.am_register(text, text), public.am_login(text, text), public.am_logout(text),
                          public.am_load(text), public.am_save(text, jsonb, int),
                          public.am_share_create(text, text, jsonb), public.am_share_get(text) to anon, authenticated;
