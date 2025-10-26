-- Looma Supabase system tables (announcements, referral codes, config extras)
-- Run in Supabase SQL editor after applying account/profile/messages schemas.

begin;

alter table if exists public.config
  add column if not exists registration_mode text not null default 'open',
  add column if not exists invite_code_required boolean not null default false,
  add column if not exists basic_posting_restricted boolean not null default false;

create table if not exists public.announcements (
  id text primary key,
  title text not null,
  body text not null,
  pinned boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by text references public.users(id) on delete set null,
  updated_by text references public.users(id) on delete set null
);

create index if not exists announcements_pinned_idx on public.announcements (pinned, created_at desc);

create table if not exists public.referral_codes (
  code text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  uses_limit integer,
  uses_count integer not null default 0,
  revoked boolean not null default false,
  created_by text references public.users(id) on delete set null,
  last_used_at timestamptz,
  metadata jsonb,
  notes text,
  used_by jsonb
);

alter table if exists public.posts
  add column if not exists status text not null default 'active';

create table if not exists public.reports (
  id text primary key,
  type text not null default 'post',
  status text not null default 'open',
  summary text,
  reason text,
  detail text,
  reporter_type text not null,
  reporter_user_id text references public.users(id) on delete set null,
  reporter_handle text,
  reporter_name text,
  target_type text not null,
  target_id text,
  target_user_id text references public.users(id) on delete set null,
  target_handle text,
  target_name text,
  post_id text references public.posts(id) on delete set null,
  comment_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists reports_status_created_idx on public.reports (status, created_at desc);

commit;
