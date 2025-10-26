-- Looma Supabase 메시지 스키마
-- Supabase SQL Editor 또는 psql 에서 실행해 주세요.

begin;

create table if not exists public.message_channels (
  id text primary key,
  type text not null check (type in ('square', 'group', 'dm')),
  name text,
  "desc" text,
  tags jsonb not null default '[]'::jsonb,
  avatar text,
  locked boolean not null default false,
  created_at timestamptz not null default now(),
  created_by text references public.users(id) on delete set null
);

create table if not exists public.message_members (
  channel_id text not null references public.message_channels(id) on delete cascade,
  user_id text not null references public.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (channel_id, user_id)
);

create table if not exists public.message_messages (
  id text primary key,
  channel_id text not null references public.message_channels(id) on delete cascade,
  author_id text references public.users(id) on delete set null,
  text text not null,
  created_at timestamptz not null default now()
);

create index if not exists message_members_user_idx
  on public.message_members (user_id, channel_id);

create index if not exists message_messages_channel_created_at_idx
  on public.message_messages (channel_id, created_at desc);

create index if not exists message_messages_author_idx
  on public.message_messages (author_id);

commit;
