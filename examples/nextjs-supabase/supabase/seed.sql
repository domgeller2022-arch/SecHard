-- Synthetic seed data for local development and the authorization tests.
--
-- These accounts and notes are fabricated. The password is a local-development value that exists
-- only in this file and only works against the local stack; it is not a credential for anything
-- else, and the addresses use the reserved `.invalid` TLD so they cannot receive mail.
--
-- Seeding runs as a privileged database role. It is deliberately separate from the unprivileged
-- clients the tests use to make assertions: a test that seeded through the application's own client
-- would be testing that client's permissions, not the boundary.

do $$
declare
  user_a uuid := '11111111-1111-4111-8111-111111111111';
  user_b uuid := '22222222-2222-4222-8222-222222222222';
begin
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change
  ) values
    ('00000000-0000-0000-0000-000000000000', user_a, 'authenticated', 'authenticated',
     'user-a@example.invalid', crypt('local-development-only', gen_salt('bf')), now(),
     '{"provider":"email","providers":["email"]}', '{"display_name":"User A"}', now(), now(), '', '', '', ''),
    ('00000000-0000-0000-0000-000000000000', user_b, 'authenticated', 'authenticated',
     'user-b@example.invalid', crypt('local-development-only', gen_salt('bf')), now(),
     '{"provider":"email","providers":["email"]}', '{"display_name":"User B"}', now(), now(), '', '', '', '')
  on conflict (id) do nothing;

  insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at, id)
  values
    (user_a, user_a, jsonb_build_object('sub', user_a::text, 'email', 'user-a@example.invalid'), 'email', now(), now(), now(), gen_random_uuid()),
    (user_b, user_b, jsonb_build_object('sub', user_b::text, 'email', 'user-b@example.invalid'), 'email', now(), now(), now(), gen_random_uuid())
  on conflict do nothing;
end $$;

-- One note per user. Seeded as a privileged role, which is why owner_id is stated explicitly here
-- rather than taken from a session.
insert into public.notes (id, owner_id, title, body) values
  ('aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111', 'User A private note', 'Only user A should be able to read this.'),
  ('bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb', '22222222-2222-4222-8222-222222222222', 'User B private note', 'Only user B should be able to read this.')
on conflict (id) do nothing;
