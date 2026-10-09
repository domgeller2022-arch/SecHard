import type { NextConfig } from 'next';

// `productionBrowserSourceMaps` is left at its default (off), which is what SEC-02's build check
// inspects: a browser bundle that ships readable source is a finding, and a private application has
// no reason to serve one.

// Route-appropriate response headers, asserted by the live HTTP recipe in the hardening repository.
//
// These are the headers every response here should carry. HSTS is deliberately absent: it is only
// meaningful over HTTPS, and sending it from a plain-HTTP local server would be a claim about
// transport security that this environment cannot make. The production transport requirement is a
// separate check, which correctly blocks while no TLS evidence exists.
//
// The CSP allows inline scripts and styles because the App Router injects its bootstrap inline;
// a nonce-based policy is the stronger production path and needs middleware nonce plumbing, which
// is recorded as a limitation rather than pretended away. Everything else is locked to 'self':
// no third-party sources, no object embedding, no framing, no base hijacks.
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
];

const config: NextConfig = {
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: false },
  // The X-Powered-By header advertises the framework and version to anyone who asks; there is no
  // reason to hand out that inventory. Removed after the external audit's M8 finding.
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default config;
