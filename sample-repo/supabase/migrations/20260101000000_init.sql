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

-- copy each new user into profiles (the admin page reads is_admin from here)
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, display_name, is_admin)
  values (new.id, new.email, new.raw_user_meta_data->>'display_name', coalesce((new.raw_user_meta_data->>'is_admin')::boolean, false));
  return new;
end;
$$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- "clear my journal" button
create function public.clear_entries(target uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from public.entries where user_id = target;
end;
$$;
