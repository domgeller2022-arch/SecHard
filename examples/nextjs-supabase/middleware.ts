import { type NextRequest } from 'next/server';
import { updateSession } from './lib/supabase/middleware';

export async function middleware(request: NextRequest) {
  return await updateSession(request);
}

// Next.js statically parses this value at build time, so it cannot be re-exported from another
// module: it has to be written literally here, and it must match the matcher used by the session
// helper. The exclusions are static assets only, so every page and route passes through the refresh.
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)'],
};
