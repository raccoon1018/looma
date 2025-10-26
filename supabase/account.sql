-- Looma Supabase account helpers
-- Run in Supabase SQL editor to enable account status lifecycle & action logs.

begin;

alter table if exists public.users
  add column if not exists status text not null default 'active',
  add column if not exists deactivated_at timestamptz,
  add column if not exists deleted_at timestamptz,
  add column if not exists suspended_until timestamptz;

create table if not exists public.user_actions (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  action text not null,
  reason text,
  detail text,
  actor_id text references public.users(id) on delete set null,
  actor_type text,
  metadata jsonb,
  created_at timestamptz not null default now()
);

create index if not exists user_actions_user_idx on public.user_actions (user_id, created_at desc);

commit;
