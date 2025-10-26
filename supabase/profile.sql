-- Looma Supabase profile helpers
-- Run in Supabase SQL editor once to enable follow 기능.
-- 섹스하고 싶다

begin;

create table if not exists public.user_follows (
  follower_id text not null references public.users(id) on delete cascade,
  target_id text not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, target_id)
);

create index if not exists user_follows_target_idx on public.user_follows (target_id);
create index if not exists user_follows_follower_idx on public.user_follows (follower_id);

commit;
