import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

/**
 * Refreshes the session on every request and protects the private routes.
 *
 * Two things worth being explicit about:
 *
 * 1. `getUser()` is used rather than `getSession()`. `getSession()` reads the cookie, which a client
 *    could have written; `getUser()` asks the auth server to validate the token. A route guard built
 *    on the former is a guard the user can edit.
 * 2. This middleware is a convenience for the user interface, not the authorization boundary. The
 *    boundary is row-level security in the database, which applies whether or not a request passed
 *    through here.
 */
export async function updateSession(request: NextRequest) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (url === undefined || key === undefined) {
    throw new Error('NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY must be set');
  }

  let response = NextResponse.next({ request });

  const supabase = createServerClient(url, key, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) {
          request.cookies.set(name, value);
        }
        response = NextResponse.next({ request });
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user === null && request.nextUrl.pathname.startsWith('/notes')) {
    const redirect = request.nextUrl.clone();
    redirect.pathname = '/';
    redirect.searchParams.set('next', request.nextUrl.pathname);
    return NextResponse.redirect(redirect);
  }

  return response;
}
