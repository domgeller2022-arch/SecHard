import { createClient } from '@/lib/supabase/server';
import { signIn } from './actions';

/**
 * Public landing page and sign-in form.
 *
 * This route is intentionally reachable without a session, which is why it is declared with
 * `auth_required: false` in the application manifest: a public page is not a bypass, and a release
 * check that flags every unauthenticated route would be wrong.
 */
export default async function Home({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  const { error } = await searchParams;

  return (
    <main>
      {user === null ? (
        <>
          <p>Sign in to see your notes.</p>
          {error === undefined ? null : (
            <p role="alert" style={{ color: '#a00' }}>
              {error}
            </p>
          )}
          <form action={signIn}>
            <p>
              <label htmlFor="email">Email</label>
              <br />
              <input id="email" name="email" type="email" required autoComplete="username" />
            </p>
            <p>
              <label htmlFor="password">Password</label>
              <br />
              <input id="password" name="password" type="password" required autoComplete="current-password" />
            </p>
            <button type="submit">Sign in</button>
          </form>
        </>
      ) : (
        <p>
          Signed in as {user.email}. <a href="/notes">Go to your notes</a>.
        </p>
      )}
    </main>
  );
}
