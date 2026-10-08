-- Atelier des Mâts · cloud sync with a nickname + PIN (no email)
-- Paste this whole file into Supabase → SQL Editor → New query → Run.
-- Safe to run again: it replaces the functions and keeps existing data.
--
-- How it works
--   * Nicknames and PINs live in our own table. PINs are stored hashed (bcrypt), never as typed.
--   * After 5 wrong PINs an account is locked: 15 minutes, then 1 hour, then 24 hours each time it happens again.
--   * Very common PINs (1234, 0000, 1111...) are refused when an ID is created.
--   * Limits per network (IP address): wrong PINs, new IDs, copies and reports, so one person can not
--     try PINs on many nicknames, flood the app with IDs, or hide someone's installation alone.
--   * Sessions that are not used for 180 days stop working.
--   * Signing in returns a random session token. The app keeps it on the device and sends it with each call.
--   * The tables are closed to the public API. The app can only use the functions below.
--   * Explore: a signed-in user can publish up to 10 installations to a public gallery that anyone can
--     browse and copy. 3 reports from different visitors hide an installation until an adult checks it
--     (Table Editor -> am_gallery -> set hidden to false, or delete the row).
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

alter table public.am_users add column if not exists locks int not null default 0;   -- how many times it got locked in a row

-- what each network (IP address) did recently, for the limits above
create table if not exists public.am_hits (
  ip   text not null,
  kind text not null,
  at   timestamptz not null default now()
);
create index if not exists am_hits_lookup on public.am_hits(ip, kind, at);

-- Closed to direct access: row level security on, and no policies.
alter table public.am_hits     enable row level security;
revoke all on public.am_hits from anon, authenticated;
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
     and last_used > now() - interval '180 days'
   returning user_id into u;
  return u;
end $$;

-- the caller's network address, as passed on by Supabase (first address of x-forwarded-for)
create or replace function public.am_ip()
returns text language plpgsql stable security definer set search_path = public, extensions as $$
declare h json;
begin
  begin h := current_setting('request.headers', true)::json; exception when others then h := null; end;
  return coalesce(nullif(h ->> 'cf-connecting-ip', ''), nullif(trim(split_part(coalesce(h ->> 'x-forwarded-for', ''), ',', 1)), ''),
                  nullif(h ->> 'x-real-ip', ''), 'unknown');
end $$;

-- count one action from this network; true if it is still under the limit for the period
create or replace function public.am_hit(p_kind text, p_max int, p_period interval)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v_ip text := am_ip(); n int;
begin
  if random() < 0.02 then delete from am_hits where at < now() - interval '2 days'; end if;   -- tidy up now and then
  select count(*) into n from am_hits h where h.ip = v_ip and h.kind = p_kind and h.at > now() - p_period;
  if n >= p_max then return false; end if;
  insert into am_hits(ip, kind) values (v_ip, p_kind);
  return true;
end $$;
-- how many times this network did it, without counting a new one
create or replace function public.am_hits_count(p_kind text, p_period interval)
returns int language sql security definer set search_path = public, extensions as $$
  select count(*)::int from am_hits where ip = am_ip() and kind = p_kind and at > now() - p_period
$$;

-- ---------- create an ID ----------
create or replace function public.am_register(p_username text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uname text := lower(trim(p_username)); uid uuid;
begin
  if uname !~ '^[a-z0-9_.-]{3,20}$' then return json_build_object('error', 'bad_username'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return json_build_object('error', 'bad_pin'); end if;
  -- the PINs people try first: all the same digit, counting up or down, and a few favourites
  if p_pin ~ '^(.)\1+$' or position(p_pin in '01234567890') > 0 or position(p_pin in '09876543210') > 0
     or p_pin in ('1212','6969','1004','2000','2580','0852','1122','1313','4444','5555','6666','7777','8888','9999','2222','3333','1111','0000','1984','1999','2001','2020','2021','2022','2023','2024','2025','2026','121212','112233','696969','159753','147258','258369') then
    return json_build_object('error', 'weak_pin');
  end if;
  if exists (select 1 from am_users where username = uname) then return json_build_object('error', 'taken'); end if;
  -- a whole troop can sign up on the same camp wifi, but not hundreds of IDs an hour
  if not am_hit('register', 30, interval '1 hour') then return json_build_object('error', 'too_many'); end if;
  insert into am_users(username, pin_hash) values (uname, crypt(p_pin, gen_salt('bf', 8))) returning id into uid;
  insert into am_library(user_id) values (uid);
  return json_build_object('token', am_new_session(uid), 'username', uname);
end $$;

-- ---------- sign in ----------
create or replace function public.am_login(p_username text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uname text := lower(trim(p_username)); u am_users;
begin
  -- one network trying PINs on many nicknames is stopped for an hour
  if am_hits_count('wrong_pin', interval '1 hour') >= 60 then
    return json_build_object('error', 'locked', 'until', now() + interval '1 hour');
  end if;
  select * into u from am_users where username = uname;
  if not found then
    perform am_hit('wrong_pin', 1000000, interval '1 hour');
    perform crypt('0000', gen_salt('bf', 8));        -- same work as a real check, so timing gives nothing away
    return json_build_object('error', 'wrong');
  end if;
  if u.locked_until is not null and u.locked_until > now() then
    return json_build_object('error', 'locked', 'until', u.locked_until);
  end if;
  if crypt(coalesce(p_pin, ''), u.pin_hash) = u.pin_hash then
    update am_users set failed = 0, locked_until = null, locks = 0 where id = u.id;
    return json_build_object('token', am_new_session(u.id), 'username', u.username);
  end if;
  perform am_hit('wrong_pin', 1000000, interval '1 hour');
  if u.failed + 1 >= 5 then
    -- each lock in a row lasts longer: 15 minutes, 1 hour, then 24 hours
    update am_users set failed = 0, locks = locks + 1,
           locked_until = now() + case when u.locks = 0 then interval '15 minutes' when u.locks = 1 then interval '1 hour' else interval '24 hours' end
     where id = u.id returning locked_until into u.locked_until;
    return json_build_object('error', 'locked', 'until', u.locked_until);
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

-- ---------- the public gallery (Explore) ----------
create table if not exists public.am_gallery (
  id         uuid primary key default gen_random_uuid(),
  owner      uuid not null references public.am_users(id) on delete cascade,
  name       text not null,
  data       jsonb not null,
  thumb      text,
  copies     int not null default 0,
  reports    int not null default 0,
  hidden     boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists am_gallery_recent on public.am_gallery(created_at desc) where not hidden;
create index if not exists am_gallery_owner on public.am_gallery(owner);
create table if not exists public.am_gallery_reports (
  item     uuid not null references public.am_gallery(id) on delete cascade,
  reporter text not null,          -- a random id kept by the reporting device, so one device counts once
  at       timestamptz not null default now(),
  primary key (item, reporter)
);
alter table public.am_gallery enable row level security;
alter table public.am_gallery_reports enable row level security;
revoke all on public.am_gallery, public.am_gallery_reports from anon, authenticated;

create or replace function public.am_gallery_publish(p_token text, p_name text, p_data jsonb, p_thumb text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := am_uid(p_token); nid uuid;
begin
  if uid is null then return json_build_object('error', 'signed_out'); end if;
  if p_data is null or jsonb_typeof(p_data -> 'lines') is distinct from 'array' then return json_build_object('error', 'bad_scene'); end if;
  if octet_length(p_data::text) > 1000000 or octet_length(coalesce(p_thumb, '')) > 120000 then return json_build_object('error', 'too_big'); end if;
  if p_thumb is not null and p_thumb !~ '^data:image/(jpeg|png);base64,' then p_thumb := null; end if;
  if (select count(*) from am_gallery where owner = uid) >= 10 then return json_build_object('error', 'limit'); end if;
  insert into am_gallery(owner, name, data, thumb)
       values (uid, left(coalesce(nullif(trim(p_name), ''), 'Installation'), 40), p_data, p_thumb) returning id into nid;
  return json_build_object('id', nid);
end $$;

create or replace function public.am_gallery_unpublish(p_token text, p_id uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := am_uid(p_token);
begin
  if uid is null then return json_build_object('error', 'signed_out'); end if;
  delete from am_gallery where id = p_id and owner = uid;
  return json_build_object('ok', true);
end $$;

-- my published installations (also the hidden ones, so their owner sees them)
create or replace function public.am_gallery_mine(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := am_uid(p_token);
begin
  if uid is null then return json_build_object('error', 'signed_out'); end if;
  return json_build_object('items', coalesce((select json_agg(json_build_object('id', id, 'name', name, 'thumb', thumb, 'copies', copies,
           'hidden', hidden, 'created_at', created_at) order by created_at desc) from am_gallery where owner = uid), '[]'::json));
end $$;

-- the gallery, newest first, a page at a time (no scene data: it is fetched when one is opened)
create or replace function public.am_gallery_list(p_offset int, p_limit int)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  return json_build_object('items', coalesce((select json_agg(x) from (
    select g.id, g.name, g.thumb, g.copies, g.created_at, u.username as "from"
      from am_gallery g join am_users u on u.id = g.owner
     where not g.hidden
     order by g.created_at desc
     offset greatest(coalesce(p_offset, 0), 0) limit least(greatest(coalesce(p_limit, 24), 1), 48)) x), '[]'::json),
    'total', (select count(*) from am_gallery where not hidden));
end $$;

create or replace function public.am_gallery_get(p_id uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare g am_gallery; who text;
begin
  select * into g from am_gallery where id = p_id and not hidden;
  if not found then return json_build_object('error', 'not_found'); end if;
  select username into who from am_users where id = g.owner;
  return json_build_object('id', g.id, 'name', g.name, 'data', g.data, 'from', who, 'created_at', g.created_at);
end $$;

-- someone saved a copy: count it
create or replace function public.am_gallery_copied(p_id uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  -- one copy per network per installation and per day, so the counter can not be pumped
  if not am_hit('copy:' || p_id::text, 1, interval '1 day') then return json_build_object('ok', true); end if;
  update am_gallery set copies = copies + 1 where id = p_id;
  return json_build_object('ok', true);
end $$;

-- 3 reports from different devices hide an installation until an adult looks at it
create or replace function public.am_gallery_report(p_id uuid, p_reporter text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare n int;
begin
  if coalesce(p_reporter, '') !~ '^[a-z0-9]{8,40}$' then return json_build_object('error', 'bad'); end if;
  if not am_hit('report', 20, interval '1 day') then return json_build_object('ok', true); end if;
  -- reports count per network, not per device: one person can not make up three devices and hide anything alone
  insert into am_gallery_reports(item, reporter) values (p_id, 'ip:' || encode(digest(am_ip(), 'sha256'), 'hex')) on conflict do nothing;
  select count(*) into n from am_gallery_reports where item = p_id;
  update am_gallery set reports = n, hidden = hidden or n >= 3 where id = p_id;
  return json_build_object('ok', true);
end $$;

-- Only these functions are callable from the app.
revoke all on function public.am_new_session(uuid), public.am_uid(text), public.am_ip(), public.am_hit(text, int, interval),
                       public.am_hits_count(text, interval) from public, anon, authenticated;
grant execute on function public.am_register(text, text), public.am_login(text, text), public.am_logout(text),
                          public.am_load(text), public.am_save(text, jsonb, int),
                          public.am_share_create(text, text, jsonb), public.am_share_get(text),
                          public.am_gallery_publish(text, text, jsonb, text), public.am_gallery_unpublish(text, uuid),
                          public.am_gallery_mine(text), public.am_gallery_list(int, int), public.am_gallery_get(uuid),
                          public.am_gallery_copied(uuid), public.am_gallery_report(uuid, text) to anon, authenticated;
