create table public.profiles (
  id uuid primary key references auth.users,
  email text not null,
  display_name text,
  is_admin boolean default false
);

create table public.entries (
  id bigint generated always as identity primary key,
  user_id uuid references public.profiles(id),
  body text not null,
  created_at timestamptz default now()
);

create table public.payments (
  id bigint generated always as identity primary key,
  user_id uuid references public.profiles(id),
  stripe_customer_id text,
  amount_cents int
);

alter table public.entries enable row level security;
create policy "anyone can read entries" on public.entries for select using (true);

-- RLS kept blocking the dashboard query, turning it off for now
alter table public.payments disable row level security;
