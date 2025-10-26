-- Looma Supabase notifications helpers
-- Run in Supabase SQL editor to enable lightweight in-app notifications.

begin;

create table if not exists public.notifications (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  type text not null,
  actor_id text references public.users(id) on delete set null,
  post_id text,
  comment_id text,
  payload jsonb,
  created_at timestamptz not null default now(),
  seen_at timestamptz
);

create index if not exists notifications_user_idx on public.notifications (user_id, created_at desc);
create index if not exists notifications_unseen_idx on public.notifications (user_id) where seen_at is null;

commit;
