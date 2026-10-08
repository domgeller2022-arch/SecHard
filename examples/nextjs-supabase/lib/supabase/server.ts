import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

/**
 * A Supabase client that acts as the signed-in user, server-side.
 *
 * The session comes from the request cookies, so every query this client makes is subject to the
 * row-level security policies as that user. That is the point: authorization lives at the data
 * boundary, and the application does not use a privileged credential to reach around it.
 *
 * The publishable key is read from the environment and is intended to be public. If it is missing,
 * the client fails loudly rather than falling back to an unauthenticated or privileged mode.
 */
export async function createClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (url === undefined || key === undefined) {
    throw new Error('NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY must be set');
  }

  const cookieStore = await cookies();

  return createServerClient(url, key, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // A Server Component cannot set cookies. The middleware refreshes the session on every
          // request, so this is expected and not an error worth surfacing.
        }
      },
    },
  });
}
