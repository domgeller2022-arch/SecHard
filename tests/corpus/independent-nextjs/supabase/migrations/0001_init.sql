create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  plan text not null default 'free',
  is_admin boolean not null default false
);

create policy "profiles_select" on public.profiles
  for select using (true) with check (true);

grant all on public.profiles to anon;

create or replace function public.make_admin(target uuid)
returns void language plpgsql security definer as $$
  update public.profiles set is_admin = true where id = target;
$$;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
