import { NextResponse, type NextRequest } from 'next/server';
import { createClient } from '@/lib/supabase/server';

/**
 * Auth callback for flows the provider completes out of band: email confirmation, magic links, and
 * recovery. Declared in the application manifest as `auth_required: false` because it must be
 * reachable before a session exists.
 *
 * The `next` parameter is validated to a fixed set of internal paths. Redirecting to an arbitrary
 * value from the query string is the classic open-redirect mistake, and "it is only a redirect" is
 * how a phishing flow gets to start on your own domain.
 */
const ALLOWED_NEXT = new Set(['/notes', '/']);

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const requestedNext = searchParams.get('next') ?? '/notes';
  const next = ALLOWED_NEXT.has(requestedNext) ? requestedNext : '/notes';

  if (code === null) {
    return NextResponse.redirect(`${origin}/?error=${encodeURIComponent('Missing confirmation code.')}`);
  }

  const supabase = await createClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error !== null) {
    return NextResponse.redirect(`${origin}/?error=${encodeURIComponent('That link is invalid or has expired.')}`);
  }

  return NextResponse.redirect(`${origin}${next}`);
}
