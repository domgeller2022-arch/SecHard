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

/**
 * The origin a redirect is built from is **configured, not derived from the request**.
 *
 * `new URL(request.url).origin` comes from the Host header, which a proxy or an attacker-supplied
 * header can influence. Building a redirect from it is the classic host-header open redirect: the
 * link looks like your domain but points elsewhere. The live check flagged exactly this when the
 * callback redirected to a host the inventory had not approved, and the fix is to stop trusting the
 * header rather than to widen the approval list.
 *
 * Production must set APP_ORIGIN to its real origin; the local default exists only for development.
 */
function trustedOrigin(): string | undefined {
  return process.env.APP_ORIGIN;
}

export async function GET(request: NextRequest) {
  const origin = trustedOrigin();
  if (origin === undefined) {
    return new NextResponse('server misconfigured: APP_ORIGIN is not set', { status: 500 });
  }
  const { searchParams } = new URL(request.url);
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
